"""
Phase 2: Agent-based drift analysis and remediation.

Uses Claude to reason about drift, classify severity, recommend remediation,
and produce actionable governance-focused output.

Recommended responsibilities:
- Classify drift severity
- Identify drift category
- Flag unmanaged resources
- Recommend remediation path
- Produce PR / pipeline-friendly summary
- Support follow-up Q&A
"""

import json
import logging
import os
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Dict, List, Optional

from anthropic import Anthropic

from tools.models import DriftReport, Drift

logger = logging.getLogger(__name__)

# USD per million tokens (input, output), keyed by model-id prefix so dated
# full IDs ('claude-haiku-4-5-20251001') match their alias row. Cache reads
# bill at ~0.1x input, cache writes (5m TTL) at 1.25x input. Prices move -
# treat a missing model as "tokens known, dollars unknown" rather than guess.
MODEL_PRICING_PER_MTOK = {
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25


@dataclass
class AgentUsage:
    """Accumulated Claude API usage for one drift-check run."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    _models: List[str] = field(default_factory=list)

    def record(self, model: str, usage: Any) -> None:
        """Add one response's usage block (tolerates absent cache fields)."""
        self.calls += 1
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0
        self.cache_creation_input_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
        self.cache_read_input_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
        if model not in self._models:
            self._models.append(model)

    @staticmethod
    def _pricing_for(model: str):
        for prefix, prices in MODEL_PRICING_PER_MTOK.items():
            if model.startswith(prefix):
                return prices
        return None

    def cost_usd(self) -> Optional[float]:
        """Estimated USD cost, or None when any model used has no price row."""
        if not self._models:
            return 0.0
        total = 0.0
        # All calls in a run use one model in practice; if several were used we
        # can't attribute tokens per model, so price only the single-model case.
        if len(self._models) > 1:
            return None
        prices = self._pricing_for(self._models[0])
        if prices is None:
            return None
        in_price, out_price = prices
        total += self.input_tokens * in_price / 1_000_000
        total += self.output_tokens * out_price / 1_000_000
        total += self.cache_read_input_tokens * in_price * CACHE_READ_MULTIPLIER / 1_000_000
        total += self.cache_creation_input_tokens * in_price * CACHE_WRITE_MULTIPLIER / 1_000_000
        return total

    def to_dict(self) -> Dict[str, Any]:
        cost = self.cost_usd()
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "models": list(self._models),
            "estimated_cost_usd": round(cost, 6) if cost is not None else None,
        }

    def summary(self) -> str:
        cost = self.cost_usd()
        cost_str = f"${cost:.4f}" if cost is not None else "unknown (no price for model)"
        return (
            f"{self.calls} Claude call(s), {self.input_tokens} in / "
            f"{self.output_tokens} out tokens"
            + (f" (+{self.cache_read_input_tokens} cache-read)" if self.cache_read_input_tokens else "")
            + f", estimated cost {cost_str}"
        )


class DriftSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class DriftCategory(str, Enum):
    RESOURCE_DRIFT = "resource_drift"
    CONFIGURATION_DRIFT = "configuration_drift"
    GOVERNANCE_DRIFT = "governance_drift"
    SECURITY_DRIFT = "security_drift"
    COST_DRIFT = "cost_drift"
    UNMANAGED_RESOURCE = "unmanaged_resource"
    SYSTEM_MANAGED = "system_managed"
    UNKNOWN = "unknown"


class RemediationAction(str, Enum):
    REDEPLOY_BICEP = "redeploy_bicep"
    ADD_TO_BICEP = "add_to_bicep"
    DELETE_RESOURCE = "delete_resource"
    UPDATE_PARAMETERS = "update_parameters"
    APPLY_POLICY_REMEDIATION = "apply_policy_remediation"
    INVESTIGATE_MANUAL_CHANGE = "investigate_manual_change"
    IGNORE_SYSTEM_MANAGED = "ignore_system_managed"
    APPROVE_EXCEPTION = "approve_exception"
    NO_ACTION = "no_action"
    UNKNOWN = "unknown"


@dataclass
class DriftFinding:
    resource_type: str
    resource_name: str
    resource_id: Optional[str]
    drift_type: str
    severity: DriftSeverity
    category: DriftCategory
    recommended_action: RemediationAction
    confidence: float
    reason: str
    details: Dict[str, Any]


class DriftAgent:
    """Uses Claude to analyse Azure/Bicep drift and suggest remediation."""

    DEFAULT_MODEL = "claude-opus-4-8"

    # Resource types that commonly indicate governance/security drift.
    GOVERNANCE_RESOURCE_TYPES = (
        "microsoft.insights/diagnosticsettings",
        "microsoft.authorization/policyassignments",
        "microsoft.authorization/policyexemptions",
        "microsoft.authorization/locks",
        "microsoft.recoveryservices/vaults",
        "microsoft.dataprotection/backupvaults",
    )

    SECURITY_SENSITIVE_RESOURCE_TYPES = (
        "microsoft.keyvault/vaults",
        "microsoft.network/azurefirewalls",
        "microsoft.network/networksecuritygroups",
        "microsoft.network/privateendpoints",
        "microsoft.network/privatednszones",
        "microsoft.authorization/roleassignments",
        "microsoft.security/",
    )

    COST_SENSITIVE_RESOURCE_TYPES = (
        "microsoft.compute/virtualmachines",
        "microsoft.sql/servers/databases",
        "microsoft.storage/storageaccounts",
        "microsoft.operationalinsights/workspaces",
        "microsoft.eventhub/namespaces",
        "microsoft.servicebus/namespaces",
        "microsoft.cache/redis",
        "microsoft.documentdb/databaseaccounts",
    )

    SYSTEM_MANAGED_RESOURCE_TYPES = (
        "microsoft.compute/disks",
        "microsoft.compute/snapshots",
        "microsoft.network/networkinterfaces",
        "microsoft.network/privateendpoints/privateDnsZoneGroups".lower(),
        "microsoft.insights/actiongroups",
    )

    HIGH_RISK_DETAIL_KEYS = (
        "publicNetworkAccess",
        "networkAcls",
        "allowBlobPublicAccess",
        "minimumTlsVersion",
        "enablePurgeProtection",
        "softDeleteRetentionInDays",
        "sku",
        "retentionInDays",
        "dailyQuotaGb",
        "identity",
        "encryption",
        "accessPolicies",
        "roleDefinitionId",
        "principalId",
    )

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_drift_items_for_prompt: int = 100,
    ):
        """
        Initialise drift agent.

        Args:
            api_key: Anthropic API key. Defaults to ANTHROPIC_API_KEY env var.
            model: Claude model. Defaults to DRIFT_AGENT_MODEL env var, then DEFAULT_MODEL.
            max_drift_items_for_prompt: Safety limit to prevent overly large prompts.
        """
        self.client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model or os.environ.get("DRIFT_AGENT_MODEL", self.DEFAULT_MODEL)
        self.max_drift_items_for_prompt = max_drift_items_for_prompt
        self.conversation_history: List[Dict[str, str]] = []
        self.usage = AgentUsage()

    def _create_message(self, **kwargs):
        """All Claude calls go through here so per-run usage/cost accumulates."""
        response = self.client.messages.create(model=self.model, **kwargs)
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.usage.record(self.model, usage)
            logger.debug(
                f"Claude call {self.usage.calls}: "
                f"{getattr(usage, 'input_tokens', 0)} in / {getattr(usage, 'output_tokens', 0)} out"
            )
        return response

    def analyze_drift(self, drift_report: DriftReport) -> str:
        """
        Analyse drift report and return a human-readable recommendation.

        Args:
            drift_report: Drift analysis from Phase 1.

        Returns:
            Human-readable analysis and recommendations.
        """
        findings = self._build_findings(drift_report)
        summary = self._build_summary(drift_report, findings)
        context = self._format_drift_context(drift_report, findings, summary)

        self.conversation_history = [
            {
                "role": "user",
                "content": context,
            }
        ]

        response = self._create_message(
            max_tokens=3000,
            system=self._get_system_prompt(),
            messages=self.conversation_history,
        )

        analysis = response.content[0].text.strip()

        self.conversation_history.append(
            {
                "role": "assistant",
                "content": analysis,
            }
        )

        return analysis

    def ask_followup(self, question: str) -> str:
        """
        Ask a follow-up question about the drift analysis.

        Maintains conversation history for context.
        """
        self.conversation_history.append(
            {
                "role": "user",
                "content": question,
            }
        )

        response = self._create_message(
            max_tokens=1500,
            system=self._get_system_prompt(),
            messages=self.conversation_history,
        )

        answer = response.content[0].text.strip()

        self.conversation_history.append(
            {
                "role": "assistant",
                "content": answer,
            }
        )

        return answer

    def get_drift_recommendation(
        self,
        resource_type: str,
        resource_name: str,
        drift_type: str,
        details: Optional[dict] = None,
        resource_id: Optional[str] = None,
    ) -> str:
        """
        Get a specific remediation recommendation for a single drift item.

        This now uses the same local classification logic as full analysis.
        """
        pseudo_drift = self._make_pseudo_drift(
            resource_type=resource_type,
            resource_name=resource_name,
            drift_type=drift_type,
            details=details or {},
            resource_id=resource_id,
        )

        finding = self._classify_drift(pseudo_drift)

        prompt = f"""
Given this Azure/Bicep drift finding, provide a concise remediation recommendation.

Resource type: {finding.resource_type}
Resource name: {finding.resource_name}
Resource ID: {finding.resource_id or "unknown"}
Drift type: {finding.drift_type}
Severity: {finding.severity}
Category: {finding.category}
Recommended action: {finding.recommended_action}
Classification reason: {finding.reason}
Details: {json.dumps(finding.details or {}, indent=2)}

Respond with:
1. Recommended action
2. Why
3. Verification command or check, if applicable
"""

        response = self._create_message(
            max_tokens=500,
            system=(
                "You are an Azure infrastructure expert. "
                "Provide brief, actionable remediation recommendations. "
                "Do not invent facts that are not present in the input."
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text.strip()

    def _build_findings(self, drift_report: DriftReport) -> List[DriftFinding]:
        drifts = drift_report.drifts or []

        findings = [self._classify_drift(drift) for drift in drifts]

        severity_order = {
            DriftSeverity.CRITICAL: 0,
            DriftSeverity.HIGH: 1,
            DriftSeverity.MEDIUM: 2,
            DriftSeverity.LOW: 3,
            DriftSeverity.INFORMATIONAL: 4,
            DriftSeverity.UNKNOWN: 5,
        }

        findings.sort(key=lambda f: severity_order.get(f.severity, 99))
        return findings

    def _classify_drift(self, drift: Drift) -> DriftFinding:
        resource_type = (getattr(drift, "resource_type", "") or "").lower()
        resource_name = getattr(drift, "resource_name", "") or "unknown"
        drift_type = (getattr(drift, "drift_type", "") or "unknown").lower()
        details = getattr(drift, "details", None) or {}
        resource_id = self._extract_resource_id(drift, details)

        category = self._classify_category(resource_type, drift_type, details)
        severity = self._classify_severity(resource_type, drift_type, details, category)
        action = self._recommend_action(drift_type, category, severity)
        confidence = self._calculate_confidence(resource_id, resource_type, drift_type, details)
        reason = self._classification_reason(resource_type, drift_type, category, severity, details)

        return DriftFinding(
            resource_type=getattr(drift, "resource_type", "unknown"),
            resource_name=resource_name,
            resource_id=resource_id,
            drift_type=getattr(drift, "drift_type", "unknown"),
            severity=severity,
            category=category,
            recommended_action=action,
            confidence=confidence,
            reason=reason,
            details=details,
        )

    def _classify_category(
        self,
        resource_type: str,
        drift_type: str,
        details: Dict[str, Any],
    ) -> DriftCategory:
        if self._matches_any(resource_type, self.SYSTEM_MANAGED_RESOURCE_TYPES):
            return DriftCategory.SYSTEM_MANAGED

        if "extra" in drift_type:
            return DriftCategory.UNMANAGED_RESOURCE

        if self._matches_any(resource_type, self.GOVERNANCE_RESOURCE_TYPES):
            return DriftCategory.GOVERNANCE_DRIFT

        if self._matches_any(resource_type, self.SECURITY_SENSITIVE_RESOURCE_TYPES):
            return DriftCategory.SECURITY_DRIFT

        if self._has_cost_sensitive_change(resource_type, details):
            return DriftCategory.COST_DRIFT

        if "modified" in drift_type:
            return DriftCategory.CONFIGURATION_DRIFT

        if "missing" in drift_type:
            return DriftCategory.RESOURCE_DRIFT

        return DriftCategory.UNKNOWN

    def _classify_severity(
        self,
        resource_type: str,
        drift_type: str,
        details: Dict[str, Any],
        category: DriftCategory,
    ) -> DriftSeverity:
        if category == DriftCategory.SYSTEM_MANAGED:
            return DriftSeverity.INFORMATIONAL

        if category == DriftCategory.SECURITY_DRIFT:
            if "missing" in drift_type or self._contains_high_risk_detail(details):
                return DriftSeverity.CRITICAL
            return DriftSeverity.HIGH

        if category == DriftCategory.GOVERNANCE_DRIFT:
            if "missing" in drift_type or "extra" in drift_type:
                return DriftSeverity.HIGH
            return DriftSeverity.MEDIUM

        if category == DriftCategory.COST_DRIFT:
            return DriftSeverity.MEDIUM

        if category == DriftCategory.UNMANAGED_RESOURCE:
            if self._matches_any(resource_type, self.SECURITY_SENSITIVE_RESOURCE_TYPES):
                return DriftSeverity.HIGH
            return DriftSeverity.MEDIUM

        if "missing" in drift_type:
            return DriftSeverity.HIGH

        if "modified" in drift_type:
            if self._contains_high_risk_detail(details):
                return DriftSeverity.HIGH
            return DriftSeverity.MEDIUM

        if "extra" in drift_type:
            return DriftSeverity.LOW

        return DriftSeverity.UNKNOWN

    def _recommend_action(
        self,
        drift_type: str,
        category: DriftCategory,
        severity: DriftSeverity,
    ) -> RemediationAction:
        if category == DriftCategory.SYSTEM_MANAGED:
            return RemediationAction.IGNORE_SYSTEM_MANAGED

        if category == DriftCategory.UNMANAGED_RESOURCE:
            return RemediationAction.INVESTIGATE_MANUAL_CHANGE

        if category == DriftCategory.GOVERNANCE_DRIFT:
            return RemediationAction.APPLY_POLICY_REMEDIATION

        if "missing" in drift_type:
            return RemediationAction.REDEPLOY_BICEP

        if "modified" in drift_type:
            return RemediationAction.REDEPLOY_BICEP

        if "extra" in drift_type:
            return RemediationAction.ADD_TO_BICEP

        if severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH):
            return RemediationAction.INVESTIGATE_MANUAL_CHANGE

        return RemediationAction.UNKNOWN

    def _calculate_confidence(
        self,
        resource_id: Optional[str],
        resource_type: str,
        drift_type: str,
        details: Dict[str, Any],
    ) -> float:
        score = 0.4

        if resource_id:
            score += 0.25

        if resource_type and resource_type != "unknown":
            score += 0.15

        if drift_type and drift_type != "unknown":
            score += 0.10

        if details:
            score += 0.10

        return round(min(score, 0.95), 2)

    def _classification_reason(
        self,
        resource_type: str,
        drift_type: str,
        category: DriftCategory,
        severity: DriftSeverity,
        details: Dict[str, Any],
    ) -> str:
        if category == DriftCategory.SYSTEM_MANAGED:
            return "Resource type is commonly created or managed by Azure as a dependent resource."

        if category == DriftCategory.GOVERNANCE_DRIFT:
            return "Resource affects governance controls such as diagnostics, policy, locks, backup, or compliance."

        if category == DriftCategory.SECURITY_DRIFT:
            return "Resource affects security-sensitive infrastructure such as Key Vault, networking, RBAC, or security controls."

        if category == DriftCategory.COST_DRIFT:
            return "Drift appears to affect a cost-sensitive resource or cost-impacting property."

        if category == DriftCategory.UNMANAGED_RESOURCE:
            return "Resource exists in Azure but does not appear to be represented in the Bicep desired state."

        if "missing" in drift_type:
            return "Resource appears in desired state but was not found in actual Azure state."

        if "modified" in drift_type:
            return "Resource exists in both desired and actual state, but one or more compared properties differ."

        return "Classification based on available drift type, resource type, and details."

    def _build_summary(
        self,
        drift_report: DriftReport,
        findings: List[DriftFinding],
    ) -> Dict[str, Any]:
        severity_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        action_counts: Dict[str, int] = {}

        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            category_counts[finding.category.value] = category_counts.get(finding.category.value, 0) + 1
            action_counts[finding.recommended_action.value] = action_counts.get(finding.recommended_action.value, 0) + 1

        return {
            "bicep_file": getattr(drift_report, "bicep_file", None),
            "resource_group": getattr(drift_report, "resource_group", None),
            "total_drift": getattr(drift_report, "total_drift", len(findings)),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "recommended_action_counts": action_counts,
            "has_blocking_drift": any(
                f.severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)
                for f in findings
            ),
        }

    def _format_drift_context(
        self,
        drift_report: DriftReport,
        findings: List[DriftFinding],
        summary: Dict[str, Any],
    ) -> str:
        limited_findings = findings[: self.max_drift_items_for_prompt]
        omitted_count = max(0, len(findings) - len(limited_findings))

        context = {
            "request": "Analyse this Azure/Bicep drift report and provide remediation recommendations.",
            "deployment_context": {
                "bicep_file": getattr(drift_report, "bicep_file", None),
                "resource_group": getattr(drift_report, "resource_group", None),
                "parameters": getattr(drift_report, "parameters", None) or {},
            },
            "summary": summary,
            "findings": [asdict(finding) for finding in limited_findings],
            "omitted_findings_count": omitted_count,
            "questions_to_answer": [
                "Which findings are most important?",
                "Which findings are likely expected Azure-managed resources?",
                "Which findings indicate unmanaged or manually created resources?",
                "Which findings should be remediated by redeploying Bicep?",
                "Which findings should be handled by Azure Policy remediation or exception tracking?",
                "What should be fixed first?",
                "What confidence limitations exist in the data?",
            ],
            "response_requirements": [
                "Be concise but actionable.",
                "Do not invent missing facts.",
                "Separate confirmed findings from assumptions.",
                "Prioritise governance, security, cost, and unmanaged resource drift.",
                "Suggest concrete next actions.",
            ],
        }

        return "# Bicep Drift Analysis Request\n\n" + json.dumps(context, indent=2, default=str)

    @staticmethod
    def _get_system_prompt() -> str:
        return """
You are an expert Azure infrastructure engineer analysing Bicep deployment drift.

Your role is to:
1. Prioritise drift findings by severity and operational impact.
2. Explain likely causes without inventing unsupported facts.
3. Identify governance, security, cost, unmanaged-resource, and system-managed drift.
4. Recommend specific remediation actions.
5. Provide confidence and data-quality caveats.
6. Prefer Resource ID based reasoning over fuzzy name matching.

Important context:
- Bicep is stateless, so drift detection requires comparing desired state with live Azure state.
- Azure Resource Graph, What-If, Azure Policy, deployment history, and Activity Logs can all provide useful signals.
- Child resources should be reasoned about by full resource ID where possible.
- System-managed resources may appear as extra resources and may not require remediation.
- Role assignments, diagnostic settings, locks, backup, public access, and policy exemptions are high-value governance/security checks.
- Cost-sensitive changes include SKU, retention, replication, capacity, VM size, workspace retention, and premium tier changes.

Output style:
- Use markdown.
- Start with an executive summary.
- Then provide priority findings.
- Then provide remediation plan.
- Then list caveats or confidence limitations.
- Be concise, practical, and suitable for an infrastructure team.
"""

    def _extract_resource_id(self, drift: Drift, details: Dict[str, Any]) -> Optional[str]:
        candidates = [
            getattr(drift, "resource_id", None),
            details.get("resource_id"),
            details.get("resourceId"),
            details.get("id"),
            details.get("targetResourceId"),
        ]

        for candidate in candidates:
            if candidate and isinstance(candidate, str):
                return candidate

        return None

    def _contains_high_risk_detail(self, details: Dict[str, Any]) -> bool:
        details_text = json.dumps(details, default=str).lower()

        return any(key.lower() in details_text for key in self.HIGH_RISK_DETAIL_KEYS)

    def _has_cost_sensitive_change(
        self,
        resource_type: str,
        details: Dict[str, Any],
    ) -> bool:
        if not self._matches_any(resource_type, self.COST_SENSITIVE_RESOURCE_TYPES):
            return False

        details_text = json.dumps(details, default=str).lower()

        cost_keywords = (
            "sku",
            "size",
            "tier",
            "capacity",
            "retention",
            "replication",
            "dailyquotagb",
            "license",
            "premium",
            "zoneRedundant".lower(),
        )

        return any(keyword in details_text for keyword in cost_keywords)

    @staticmethod
    def _matches_any(value: str, prefixes: tuple) -> bool:
        value = (value or "").lower()

        return any(value.startswith(prefix.lower()) for prefix in prefixes)

    @staticmethod
    def _make_pseudo_drift(
        resource_type: str,
        resource_name: str,
        drift_type: str,
        details: Dict[str, Any],
        resource_id: Optional[str] = None,
    ) -> Drift:
        """
        Creates a lightweight Drift-like object.

        This avoids requiring the caller to construct a full Drift model
        for single-item recommendations.
        """

        class PseudoDrift:
            pass

        pseudo = PseudoDrift()
        pseudo.resource_type = resource_type
        pseudo.resource_name = resource_name
        pseudo.resource_id = resource_id
        pseudo.drift_type = drift_type
        pseudo.details = details

        return pseudo  # type: ignore
