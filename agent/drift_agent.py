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
from dataclasses import dataclass, asdict, field, replace
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
    # Attribution from the report's change_origin (origin, changed_by, category,
    # reason). Given to the agent so it cites who/how instead of re-deriving it.
    change_origin: Optional[Dict[str, Any]] = None
    # Sibling properties of the LIVE resource that did not drift (see
    # LIVE_CONTEXT_PROPERTIES). details carries only the CHANGED paths, so
    # without this the analysis cannot see the state that bounds a finding's
    # severity or decides whether a remediation is even possible - and correctly
    # refuses to assert it, producing "unverified" hedges about facts the report
    # already holds.
    live_context: Optional[Dict[str, Any]] = None


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

    # Live properties attached to every finding as `live_context`. Deliberately
    # a short allowlist, not the whole resource: a single live payload can run
    # to thousands of tokens (the AI account's callRateLimit alone is ~8k), and
    # the analysis only needs the state that changes its ANSWER -
    #   - a sibling that BOUNDS the blast radius of the drifted property
    #     (publicNetworkAccess Disabled while networkAccessPolicy opened to
    #     AllowAll: real drift, bounded exposure - stating one without the other
    #     overstates it),
    #   - or state that decides whether the remediation is even POSSIBLE
    #     (sku.capacity 0 means encryptionAtHost can be written; diskState /
    #     managedBy say whether a disk is attached and therefore in use).
    # Paths are dotted and resolved leniently - a resource type that has none of
    # them simply gets an empty context.
    LIVE_CONTEXT_PROPERTIES = (
        "sku.capacity",
        "zones",
        "properties.provisioningState",
        "properties.publicNetworkAccess",
        "properties.networkAccessPolicy",
        "properties.diskState",
        "properties.managedBy",
        "properties.encryption.type",
        "properties.minimumTlsVersion",
        "properties.allowBlobPublicAccess",
        "properties.enableRbacAuthorization",
        "properties.enablePurgeProtection",
        "properties.disableLocalAuth",
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
        # matched_unresolvable entries are NOT drift - they record that a
        # runtime-named resource was reconciled to its deployed counterpart.
        # Feeding them to the analysis as findings both inflates the prompt
        # (they dominated real estates ~30:3) and degrades the output: the
        # model spends its answer caveating "unresolved" rows instead of
        # analysing the actionable drift. They are reduced to a count.
        all_drifts = drift_report.drifts or []
        actionable = [d for d in all_drifts if d.drift_type != "matched_unresolvable"]
        reconciled_count = len(all_drifts) - len(actionable)
        if reconciled_count:
            drift_report = replace(drift_report, drifts=actionable)

        findings = self._build_findings(drift_report)
        summary = self._build_summary(drift_report, findings)
        context = self._format_drift_context(
            drift_report, findings, summary, reconciled_count=reconciled_count
        )

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

        live_by_key = self._index_live_resources(drift_report.live_resources)
        findings = [self._classify_drift(drift) for drift in drifts]
        for finding in findings:
            finding.live_context = self._extract_live_context(finding, live_by_key)

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

    @staticmethod
    def _index_live_resources(live_resources) -> Dict[str, Dict[str, Any]]:
        """Index live resources by resource ID and by (type, name).

        Both keys because a finding may carry only one of them: property drift
        records reliably have a resource_id from attribution, while a
        missing/extra record may only have type+name.
        """
        index: Dict[str, Dict[str, Any]] = {}
        for resource in live_resources or []:
            if not isinstance(resource, dict):
                continue
            resource_id = resource.get("id")
            if resource_id:
                index[str(resource_id).lower()] = resource
            rtype, name = resource.get("type"), resource.get("name")
            if rtype and name:
                index[f"{str(rtype).lower()}/{str(name).lower()}"] = resource
        return index

    def _extract_live_context(
        self,
        finding: DriftFinding,
        live_by_key: Dict[str, Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Pull the LIVE_CONTEXT_PROPERTIES present on this finding's resource.

        Only properties that did NOT drift are included - a value already in
        `details` would just be repeated at a second, contradictory-looking
        path. Returns None when nothing matched, so a resource with no relevant
        siblings adds nothing to the prompt.
        """
        if not live_by_key:
            return None
        live = None
        if finding.resource_id:
            live = live_by_key.get(finding.resource_id.lower())
        if live is None:
            key = f"{(finding.resource_type or '').lower()}/{(finding.resource_name or '').lower()}"
            live = live_by_key.get(key)
        if live is None:
            return None

        changed = (finding.details or {}).get("changed_properties") or {}
        changed_paths = {str(p).lower() for p in changed} if isinstance(changed, dict) else set()

        context: Dict[str, Any] = {}
        for path in self.LIVE_CONTEXT_PROPERTIES:
            if path.lower() in changed_paths:
                continue
            value = self._resolve_path(live, path)
            if value is not None:
                context[path] = value
        return context or None

    @staticmethod
    def _resolve_path(resource: Dict[str, Any], path: str) -> Any:
        node: Any = resource
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
            if node is None:
                return None
        return node

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
            change_origin=getattr(drift, "change_origin", None),
        )

    def _classify_category(
        self,
        resource_type: str,
        drift_type: str,
        details: Dict[str, Any],
    ) -> DriftCategory:
        # SYSTEM_MANAGED is a statement about PROVENANCE - Azure created this
        # resource as a dependent (a VM's NIC, a private endpoint's DNS zone
        # group) - and it exists to stop that churn being reported as drift.
        # It must not swallow a PROPERTY drift: a property drift means the
        # comparator matched a resource DECLARED in the Bicep against its live
        # counterpart, so the resource is template-managed by definition and
        # its properties are the operator's to control. A live round proved the
        # cost: disk-drift-data is declared in Bicep, was manually flipped
        # networkAccessPolicy DenyAll -> AllowAll, and the type-based shortcut
        # classified that security regression "ignore_system_managed".
        if self._matches_any(resource_type, self.SYSTEM_MANAGED_RESOURCE_TYPES) and not (
            "modified" in drift_type or "property" in drift_type
        ):
            return DriftCategory.SYSTEM_MANAGED

        if "extra" in drift_type:
            return DriftCategory.UNMANAGED_RESOURCE

        if self._matches_any(resource_type, self.GOVERNANCE_RESOURCE_TYPES):
            return DriftCategory.GOVERNANCE_DRIFT

        if self._matches_any(resource_type, self.SECURITY_SENSITIVE_RESOURCE_TYPES):
            return DriftCategory.SECURITY_DRIFT

        if self._has_cost_sensitive_change(resource_type, details):
            return DriftCategory.COST_DRIFT

        if "modified" in drift_type or "property" in drift_type:
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

        # The property-drift detector assigns per-property severity (CRITICAL_
        # PROPERTIES, security sentinels). A critical property is authoritative
        # regardless of category heuristics - without this, an ACR admin-user
        # or storage https-only drift classified as finding severity "unknown".
        property_severity = self._max_property_severity(details)
        if property_severity == DriftSeverity.CRITICAL:
            return DriftSeverity.CRITICAL

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

        if "modified" in drift_type or "property" in drift_type:
            if property_severity is not None:
                return property_severity
            if self._contains_high_risk_detail(details):
                return DriftSeverity.HIGH
            return DriftSeverity.MEDIUM

        if "extra" in drift_type:
            return DriftSeverity.LOW

        return DriftSeverity.UNKNOWN

    # Detector per-property severities are info/warning/critical; map them to
    # finding-level severities (warning is actionable but not urgent).
    _PROPERTY_SEVERITY_RANK = (
        ("critical", DriftSeverity.CRITICAL),
        ("warning", DriftSeverity.MEDIUM),
        ("info", DriftSeverity.LOW),
    )

    def _max_property_severity(self, details: Dict[str, Any]) -> Optional[DriftSeverity]:
        """Highest detector-assigned severity across changed_properties, or None."""
        changed = (details or {}).get("changed_properties")
        if not isinstance(changed, dict):
            return None
        labels = {
            (change.get("severity") or "").lower()
            for change in changed.values()
            if isinstance(change, dict)
        }
        for label, severity in self._PROPERTY_SEVERITY_RANK:
            if label in labels:
                return severity
        return None

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

        if "modified" in drift_type or "property" in drift_type:
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

        if "modified" in drift_type or "property" in drift_type:
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
        reconciled_count: int = 0,
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
            "reconciled_resources": {
                "count": reconciled_count,
                "note": (
                    "Runtime-named resources (uniqueString/format) reconciled to "
                    "their deployed counterparts by smart matching. Informational, "
                    "NOT drift - excluded from findings; do not analyse or caveat them."
                ),
            } if reconciled_count else None,
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

        if not reconciled_count:
            context.pop("reconciled_resources", None)

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
- Child resources should be reasoned about by full resource ID where possible.
- System-managed resources may appear as extra resources and may not require remediation.
- Role assignments, diagnostic settings, locks, backup, public access, and policy exemptions are high-value governance/security checks.
- Cost-sensitive changes include SKU, retention, replication, capacity, VM size, workspace retention, and premium tier changes.

Attribution is already resolved for you - do NOT recommend pulling Activity Logs to find who/when:
- Each finding carries `change_origin` (origin, category, changed_by, reason) and a `resource_id`. This is the answer to "who changed this and how", already correlated from the activity log.
- origin `manual_change` / category `out_of_band` = a change made outside the pipeline (portal or CLI edit); origin `authorized_deployment` = a pipeline identity. "out_of_band" means it bypassed the IaC pipeline - NOT that the actor lacked permission, so describe it as an out-of-band/manual change, not an "unauthorized" or malicious act. Cite `changed_by` and the origin directly; only suggest deeper log investigation if `change_origin` is unknown/absent.

Remediation guidance (Azure specifics - apply these, they are common mistakes):
- Resource LOCKS do not stop configuration drift. A `CanNotDelete` lock only blocks deletion, so it prevents NONE of a property change, an added rule, or a security-setting flip - never recommend it as prevention for modification drift. `ReadOnly` would block modifications but also blocks your own deployment pipeline, so it is usually unusable. The real prevention for out-of-band edits is RBAC that restricts portal/CLI write access plus pipeline-only deployment - recommend that instead.
- Scope the redeploy to the NARROWEST unit that fixes the drift - the specific module or resource - not the whole `main.bicep`. A full-estate `what-if`/deploy to revert one resource has a large, unnecessary blast radius.
- Bicep resource collections are replaced as a whole on redeploy (a PUT overwrites the array), so a redeploy removes rogue elements ADDED inside a managed collection. It does NOT delete a rogue TOP-LEVEL child added out-of-band (e.g. a standalone rule-collection group, a firewall rule) - that needs an explicit `az ... delete`. Say which case applies before promising a redeploy will clean it up.
- Redeploy fixes declarative resources (firewall policy, RCGs, NSGs, Key Vault config). Do not claim "atomic, no sequencing" - some children require serialized writes the template already encodes via dependsOn; that ordering is the template's concern, not a manual step.
- When live is MORE secure/hardened than the template (encryptionAtHost or infrastructure encryption on, a customer-managed key applied, TLS floor raised, public access closed, secure boot/vTPM on), do NOT simply say "redeploy will revert it". Such settings are commonly enforced by an Azure Policy assignment at subscription or management-group scope, so the enforcement scope must be checked FIRST: `az policy assignment list --scope /subscriptions/<sub> --disable-scope-strict-match` (that flag is what surfaces assignments inherited from ancestor management groups).
  Finding an assignment is only half the check. Built-in hardening policies do NOT have a fixed effect - they expose `effect` as a PARAMETER (typically Audit / Deny / Disabled) and the assignment chooses it, so you must read `parameters.effect.value` on the assignment, not assume from the policy's name. THREE outcomes, and they differ completely - say which one applies:
  - `Audit` - the DEFAULT for most built-ins, and the DANGEROUS one because nothing stops you. The redeploy SUCCEEDS, the hardening is silently downgraded, and the only trace is a non-compliant row in Policy that nobody is watching. This is the case the whole warning exists for: never let "there is a policy" be read as "something will protect me".
  - `Deny` - the redeploy FAILS outright with a policy violation. Loud and safe; tell the operator to expect a deployment error, not silent re-drift.
  - `Modify` / `deployIfNotExists` - the write is rewritten or re-applied, so the redeploy "succeeds" and the SAME drift is back on the next run, which reads as a broken remediation.
  Then give the branches: if anything enforces it (any effect), the durable fix is to update the Bicep to declare the enforced value so template and reality agree; only if nothing enforces it is reverting-by-redeploy a real choice, and even then it is a deliberate security downgrade needing an owner's sign-off.
- Do NOT invent a subscription-level "encryption default" that flips a per-resource security flag. `Microsoft.Compute/EncryptionAtHost` is a subscription FEATURE REGISTRATION - it only permits the setting, it never applies it, so its state explains nothing about an encryptionAtHost drift. A default disk encryption set IS subscription+region scoped, but it governs CMK-vs-platform-key on DISKS (`properties.encryption.type`) - a different property. Do not send someone to check one for drift in the other.
- `encryptionAtHost` cannot be changed while instances are allocated - Azure rejects the write on a VM/VMSS that is running. If you recommend changing it, say the resource must be deallocated first (a VMSS at `sku.capacity: 0` already satisfies this - check the capacity before adding the caveat or omitting it).
- The report's own `policy_enforced_drifts` split only catches enforcement it could correlate from the activity log. A finding attributed to a named user is NOT proof no policy is involved - the user may have tripped a policy, or the policy remediation may predate the log window. Do not present absence of policy attribution as "confirmed manual".

Evidence discipline (a live round produced both of these errors - they read as authoritative and are simply untrue):
- Never assert a RELATIONSHIP that is not in the data. Attachment, dependency, and "used by X" claims must come from a field you were given (a resource ID reference, a parent/child name). Do not infer that a disk is attached to a scale set, that a subnet is used by an app, or that a rule protects a workload because the names look related. If the wiring matters to your recommendation and is absent, say it is unverified and name the check - do not assume it.
- State the MITIGATING fields, not just the alarming one. A finding is a set of properties: if `networkAccessPolicy` opened to AllowAll but `publicNetworkAccess` is still Disabled, or a port opened but the NSG still denies it, the exposure is bounded and you must say so in the same breath. Reporting the worst property alone, when a sibling in the same payload constrains it, overstates severity and burns the reader's trust.
- `live_context` on each finding carries live sibling properties that did NOT drift, precisely so the two rules above are answerable: it is where you find the mitigating value, the allocation state (`sku.capacity`), and whether a disk is attached (`properties.diskState`, `properties.managedBy`). USE IT before saying something is unverified - hedging on a value that was handed to you is as wrong as inventing one. Only what is absent from both `details` and `live_context` is genuinely unknown, and then you name the command that would settle it.

Plan consistency (a live round produced a plan whose second step failed on a constraint its own third step documented):
- A constraint you identify anywhere in the findings BINDS every later step that touches that resource. If you say a property is immutable, then a redeploy of the module DECLARING that property does not "fix another property first" - the same PUT carries the immutable value and Azure rejects it. Reconcile the template to reality (or migrate the resource) BEFORE the step that needs the deploy to succeed, and say that is why the order is what it is.
- When a property is immutable, ALWAYS offer BOTH ways out and let the owner choose - do not present the expensive one as the only one:
  (a) RECONCILE: change the Bicep to declare the value that is live. Cheap, instant, no data movement. Lead with it when the resource is idle or disposable - `properties.diskState: Unattached`, `sku.capacity: 0`, an empty test resource - because there is nothing to preserve and the drift is then genuinely closed.
  (b) MIGRATE: snapshot/recreate/re-point to force reality back to the template. Only worth it when the declared value is a real requirement (a zone the workload must sit in, a region for residency). Say what makes it worth the cost.
  Reconciling is not "giving up": an unattached 4GB disk in the wrong zone is a template that is wrong about an idle resource, not an outage waiting to happen.
- ORDER the steps, do not merely cross-reference them. The plan is a numbered list an operator works top to bottom; a warning that lives in step 4 does not save the reader from step 3 having already failed. The step that unblocks a deploy must be NUMBERED EARLIER than the deploy it unblocks. "Do this before or separately from step N" is not acceptable when you could simply have put it before step N.
- Before you write the remediation plan, re-read your own findings and check each step against them. For every resource touched by more than one step, ask: if someone runs these in the order written, does step k succeed given what steps 1..k-1 did and what my findings say is possible? If not, reorder or merge - do not annotate.

Output style:
- Use markdown.
- Start with a "## TL;DR" section: 2-4 sentences a busy engineer can read in
  ten seconds - what drifted, how bad, and the single next action.
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
