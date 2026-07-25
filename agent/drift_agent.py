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
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any

from anthropic import Anthropic

from tools.models import Drift, DriftReport

from .usage import AgentUsage
from .findings import DriftSeverity, DriftCategory, RemediationAction, DriftFinding
from .prompts import PromptsMixin

logger = logging.getLogger(__name__)




class DriftAgent(PromptsMixin):
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
    # NOT in this list, deliberately: `zones`. It is a drift TARGET, not
    # context - it bounds no blast radius and decides no remediation. Carrying
    # it made a VMSS finding (whose zones never drifted) arrive with
    # zones: ["1","2","3"] in its payload, and the analysis reported in its
    # TL;DR that "both resources drifted a zones value that is immutable" -
    # contradicting its own body two sections later. Anything whose live value
    # could be mistaken for a mismatch belongs in details or nowhere.
    LIVE_CONTEXT_PROPERTIES = (
        "sku.capacity",
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
        api_key: str | None = None,
        model: str | None = None,
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
        self.conversation_history: list[dict[str, str]] = []
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
        details: dict | None = None,
        resource_id: str | None = None,
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

    def _build_findings(self, drift_report: DriftReport) -> list[DriftFinding]:
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
    def _index_live_resources(live_resources) -> dict[str, dict[str, Any]]:
        """Index live resources by resource ID and by (type, name).

        Both keys because a finding may carry only one of them: property drift
        records reliably have a resource_id from attribution, while a
        missing/extra record may only have type+name.
        """
        index: dict[str, dict[str, Any]] = {}
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
        live_by_key: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
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

        context: dict[str, Any] = {}
        for path in self.LIVE_CONTEXT_PROPERTIES:
            if path.lower() in changed_paths:
                continue
            value = self._resolve_path(live, path)
            if value is not None:
                context[path] = value
        return context or None

    @staticmethod
    def _resolve_path(resource: dict[str, Any], path: str) -> Any:
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
        details: dict[str, Any],
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
        details: dict[str, Any],
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

    def _max_property_severity(self, details: dict[str, Any]) -> DriftSeverity | None:
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
        resource_id: str | None,
        resource_type: str,
        drift_type: str,
        details: dict[str, Any],
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
        details: dict[str, Any],
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




    def _extract_resource_id(self, drift: Drift, details: dict[str, Any]) -> str | None:
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

    def _contains_high_risk_detail(self, details: dict[str, Any]) -> bool:
        details_text = json.dumps(details, default=str).lower()

        return any(key.lower() in details_text for key in self.HIGH_RISK_DETAIL_KEYS)

    def _has_cost_sensitive_change(
        self,
        resource_type: str,
        details: dict[str, Any],
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
        details: dict[str, Any],
        resource_id: str | None = None,
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
