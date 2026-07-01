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
import os
import re
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

from anthropic import Anthropic

from tools.models import DriftReport, Drift


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


@dataclass
class DriftAgentResult:
    summary: Dict[str, Any]
    findings: List[DriftFinding]
    llm_analysis: str
    raw_llm_json: Optional[Dict[str, Any]] = None


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

    def analyze_drift(
        self,
        drift_report: DriftReport,
        include_json: bool = False,
    ) -> str:
        """
        Analyse drift report and return a human-readable recommendation.

        Args:
            drift_report: Drift analysis from Phase 1.
            include_json: If True, append structured finding JSON to the response.

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

        response = self.client.messages.create(
            model=self.model,
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

        if include_json:
            result = DriftAgentResult(
                summary=summary,
                findings=findings,
                llm_analysis=analysis,
            )
            return analysis + "\n\n```json\n" + json.dumps(self._serialise_result(result), indent=2) + "\n```"

        return analysis

    def analyze_drift_structured(self, drift_report: DriftReport) -> DriftAgentResult:
        """
        Analyse drift report and return structured result.

        This is useful if the next phase needs to create Jira tickets,
        GitHub comments, dashboards, or remediation workflows.
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

        response = self.client.messages.create(
            model=self.model,
            max_tokens=3500,
            system=self._get_structured_system_prompt(),
            messages=self.conversation_history,
        )

        text = response.content[0].text.strip()
        parsed = self._try_parse_json(text)

        return DriftAgentResult(
            summary=summary,
            findings=findings,
            llm_analysis=text,
            raw_llm_json=parsed,
        )

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

        response = self.client.messages.create(
            model=self.model,
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

        response = self.client.messages.create(
            model=self.model,
            max_tokens=500,
            system=(
                "You are an Azure infrastructure expert. "
                "Provide brief, actionable remediation recommendations. "
                "Do not invent facts that are not present in the input."
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text.strip()

    def generate_pipeline_comment(self, drift_report: DriftReport) -> str:
        """
        Generate a PR or pipeline-friendly markdown comment.

        Useful for GitHub Actions, Azure DevOps, Buildkite, or pull request checks.
        """
        findings = self._build_findings(drift_report)
        summary = self._build_summary(drift_report, findings)

        critical = summary["severity_counts"].get(DriftSeverity.CRITICAL.value, 0)
        high = summary["severity_counts"].get(DriftSeverity.HIGH.value, 0)

        status = "passed"
        if critical > 0:
            status = "failed"
        elif high > 0:
            status = "warning"

        lines = [
            "## Bicep Drift Analysis",
            "",
            f"**Status:** `{status}`",
            f"**Total drift items:** {summary['total_drift']}",
            "",
            "### Severity Summary",
        ]

        for severity, count in summary["severity_counts"].items():
            lines.append(f"- **{severity}:** {count}")

        lines.extend(
            [
                "",
                "### Top Findings",
            ]
        )

        for finding in findings[:10]:
            lines.append(
                f"- `{finding.severity}` `{finding.category}` "
                f"`{finding.drift_type}` - "
                f"{finding.resource_type} / {finding.resource_name} "
                f"→ {finding.recommended_action}"
            )

        if len(findings) > 10:
            lines.append(f"- ...and {len(findings) - 10} more findings.")

        lines.extend(
            [
                "",
                "### Recommended Next Step",
                self._get_pipeline_next_step(summary),
            ]
        )

        return "\n".join(lines)

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

    @staticmethod
    def _get_structured_system_prompt() -> str:
        return """
You are an expert Azure infrastructure engineer analysing Bicep deployment drift.

Return valid JSON only.

The JSON schema should be:
{
  "executiveSummary": "string",
  "overallRisk": "critical | high | medium | low | informational | unknown",
  "priorityFindings": [
    {
      "resourceType": "string",
      "resourceName": "string",
      "severity": "critical | high | medium | low | informational | unknown",
      "category": "string",
      "issue": "string",
      "likelyCause": "string",
      "recommendation": "string",
      "confidence": "high | medium | low"
    }
  ],
  "remediationPlan": [
    {
      "priority": 1,
      "action": "string",
      "ownerHint": "platform | workload | security | governance | unknown",
      "verification": "string"
    }
  ],
  "exceptionsToConsider": [
    {
      "resourceName": "string",
      "reason": "string"
    }
  ],
  "dataQualityCaveats": [
    "string"
  ]
}

Do not include markdown.
Do not invent facts.
If information is missing, say so explicitly in the relevant field.
"""

    def _get_pipeline_next_step(self, summary: Dict[str, Any]) -> str:
        if summary["severity_counts"].get(DriftSeverity.CRITICAL.value, 0) > 0:
            return "Block promotion and investigate critical drift before deployment continues."

        if summary["severity_counts"].get(DriftSeverity.HIGH.value, 0) > 0:
            return "Require platform review before promotion. High-severity drift should be remediated or exception-approved."

        if summary["severity_counts"].get(DriftSeverity.MEDIUM.value, 0) > 0:
            return "Allow deployment with a follow-up remediation task if the drift is understood."

        return "No blocking drift detected. Continue with normal deployment checks."

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
    def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _serialise_result(result: DriftAgentResult) -> Dict[str, Any]:
        return {
            "summary": result.summary,
            "findings": [asdict(finding) for finding in result.findings],
            "llm_analysis": result.llm_analysis,
            "raw_llm_json": result.raw_llm_json,
        }

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
