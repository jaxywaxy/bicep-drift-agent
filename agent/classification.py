"""
agent/classification.py

The deterministic, LLM-free heart of the agent: turns each Drift into a
DriftFinding - severity, category, recommended action, confidence, and a
human-readable reason - using resource-type policy tables (governance / security
/ cost / system-managed) and the per-property severity rank. No Anthropic client
here, so this is fully unit-testable without an API key. DriftAgent inherits it
as a mixin; the orchestrator calls self._build_findings / self._classify_drift.
"""

import json
from typing import Any

from tools.models import Drift, DriftReport
from .findings import DriftFinding, DriftSeverity, DriftCategory, RemediationAction


class DriftClassifier:
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
