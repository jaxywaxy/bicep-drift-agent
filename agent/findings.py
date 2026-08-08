"""
agent/findings.py

Finding data types shared across the agent package: the drift severity /
category / remediation-action enums and the DriftFinding record the
classifier produces and the prompt builder serialises. No behaviour here -
just the vocabulary the mixins and orchestrator agree on.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


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
    resource_id: str | None
    drift_type: str
    severity: DriftSeverity
    category: DriftCategory
    recommended_action: RemediationAction
    confidence: float
    reason: str
    details: dict[str, Any]
    # Attribution from the report's change_origin (origin, changed_by, category,
    # reason). Given to the agent so it cites who/how instead of re-deriving it.
    change_origin: dict[str, Any] | None = None
    # Sibling properties of the LIVE resource that did not drift (see
    # LIVE_CONTEXT_PROPERTIES). details carries only the CHANGED paths, so
    # without this the analysis cannot see the state that bounds a finding's
    # severity or decides whether a remediation is even possible - and correctly
    # refuses to assert it, producing "unverified" hedges about facts the report
    # already holds.
    live_context: dict[str, Any] | None = None
    # The most recent lifecycle operation that did NOT succeed, if any.
    #
    # The report holds this and the analysis never saw it. On the first live
    # prod scan a Key Vault was missing because the redeploy had been BLOCKED by
    # a soft-deleted vault of the same name: the lifecycle carried
    # `create / Started` by the pipeline identity and no completion. Given only
    # change_origin, the analysis said the cause was "unknown, may predate the
    # logs" - faithful to what it was handed, and wrong - then recommended
    # hand-writing a replacement vault, which would have failed the same way.
    #
    # A create that started and never finished is the difference between "who
    # deleted this?" and "your deployment failed"; those have no remediation in
    # common.
    unfinished_operation: dict[str, Any] | None = None
    # Private endpoints whose privateLinkServiceId targets THIS resource.
    #
    # live_context carries sibling properties of the same resource, which cannot
    # answer "is closing public access safe?" - that depends on a DIFFERENT
    # resource. Live: a Key Vault whose publicNetworkAccess had been flipped to
    # Enabled was analysed without any reference to `jacquiprod-pe-kv`, which sat
    # in live_resources the whole time. The narrative correctly refused to
    # conclude, saying the report "proves public reachability was enabled but not
    # that anonymous access is possible" - honest, and one lookup short of the
    # actual answer.
    private_endpoints: list[dict[str, Any]] | None = None
    # Policy assignments whose scope contains this resource.
    #
    # EVIDENCE, not attribution: an in-scope assignment is a candidate
    # explanation for a value that keeps returning, never proof. The report's
    # own attribution only recognises the two BUILT-IN inherit-tag policies
    # (tools.policy.INHERIT_TAG_DEFINITIONS), so a CUSTOM Modify policy's
    # imposed value arrives as ordinary actionable drift attributed to whoever
    # wrote it. Live: a custom `drift-inherit-environment` assignment rewrote
    # tags.environment on two resources and the pipeline credited the deployer.
    related_policy_assignments: list[dict[str, Any]] | None = None
