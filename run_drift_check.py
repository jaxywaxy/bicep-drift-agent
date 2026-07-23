"""
run_drift_check.py

Phase 1 entry point — runs the full drift check WITHOUT an agent loop.
Get this working first. The agent comes later.

Usage:
    python run_drift_check.py <bicep-file> <resource-group>

Example:
    python run_drift_check.py ./infra/main.bicep my-resource-group
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from tools.compile_bicep import (
    compile_bicep,
    detect_deployment_scope,
    extract_resources_from_arm,
)
from tools.deployment_stacks import (
    annotate_stack_ownership,
    compare_deployment_stack,
    dedupe_against,
    fetch_deployment_stack,
    load_stack_config,
    stack_drift_enabled,
)
from tools.diff_states import ResourceDrift, diff_states, format_drift_report
from tools.get_live_state import (
    fetch_cross_subscription_resources,
    fetch_declared_defender_pricings,
    get_live_state,
    qualify_extension_resource_names,
)
from tools.ignore_patterns import IgnorePatternList
from tools.logger import get_logger, setup_logging
from tools.policy import (
    compare_policy_resources,
    fetch_policy_resources,
    policy_drift_enabled,
)
from tools.rbac import (
    collect_managed_identity_principals,
    compare_role_assignments,
    fetch_role_assignments,
    rbac_enabled,
)
from tools.redact import redact_secrets
from tools.rg_selector import rg_label

logger = get_logger(__name__)


def _load_arm_parameters_env() -> dict:
    """Parse ARM_PARAMETERS if set. Returns {} on absence or bad JSON."""
    raw = os.environ.get("ARM_PARAMETERS")
    if not raw:
        return {}
    try:
        params = json.loads(raw)
        logger.debug(f"Parameters from ARM_PARAMETERS: {params}")
        return params
    except json.JSONDecodeError:
        logger.warning("Invalid JSON in ARM_PARAMETERS")
        return {}


def _load_bicepparam_file(bicep_file: str, resource_group: str) -> dict:
    """Read parameters/<env>.bicepparam next to the bicep file (env = last RG segment).

    Simple line-by-line parser: `param name = 'value'` -> {name: "value"}. Strips
    // comments and surrounding quotes. Non-string types come out as strings -
    fine for condition gates, imperfect for numeric/boolean resource properties
    (see docs/CONFIGURATION_REFERENCE.md).
    """
    environment = resource_group.split('-')[-1]  # rg-prod → prod
    bicepparam_file = Path(bicep_file).parent / "parameters" / f"{environment}.bicepparam"
    if not bicepparam_file.exists():
        return {}
    try:
        with open(bicepparam_file, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning(f"Could not load {bicepparam_file.name}: {e}")
        return {}

    params: dict = {}
    for line in content.split('\n'):
        line = line.strip()
        if not (line.startswith('param ') and '=' in line):
            continue
        line = line.split('//')[0].strip()
        parts = line.replace('param ', '').split('=', 1)
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        value = parts[1].strip().strip("'\"")
        if value:  # skip empty values
            params[key] = value
    if params:
        logger.debug(f"Parameters loaded from {bicepparam_file.name}: {params}")
    return params


def _load_arm_parameters_json(bicep_file: str) -> dict:
    """Read a sibling ARM parameters.json (standard `az deployment` layout).

    Flattens {parameters: {k: {value: v}}} -> {k: v}; keeps dict/list values
    intact so object params (tags) resolve as real objects.
    """
    params_json = Path(bicep_file).parent / "parameters.json"
    if not params_json.exists():
        return {}
    try:
        with open(params_json, encoding="utf-8") as f:
            raw = json.load(f).get("parameters", {})
    except Exception as e:
        logger.warning(f"Could not load {params_json}: {e}")
        return {}
    params = {
        k: v.get("value") for k, v in raw.items()
        if isinstance(v, dict) and "value" in v
    }
    if params:
        logger.info(f"Parameters loaded from {params_json}: {sorted(params)}")
    return params


def _resolve_parameter_overrides(bicep_file: str, resource_group: str) -> dict:
    """Resolve parameter overrides in precedence order: env > bicepparam > parameters.json."""
    env_params = _load_arm_parameters_env()
    if env_params:
        return env_params
    bicepparam = _load_bicepparam_file(bicep_file, resource_group)
    if bicepparam:
        return bicepparam
    return _load_arm_parameters_json(bicep_file)


def _compile_and_extract(bicep_file: str, param_overrides: dict) -> tuple[list[dict], str]:
    """Compile Bicep → ARM and extract resources. Returns (arm_resources, deployment_scope)."""
    logger.info("Step 1: Compiling Bicep template...")
    try:
        arm_template = compile_bicep(bicep_file)
    except RuntimeError as e:
        logger.error(f"Failed to compile Bicep: {e}")
        raise

    deployment_scope = detect_deployment_scope(arm_template)
    if deployment_scope == "subscription":
        logger.info("Detected subscription-scoped template (Landing Zone)")

    try:
        arm_resources = extract_resources_from_arm(arm_template, param_overrides)
    except Exception as e:
        logger.error(f"Failed to extract resources: {e}", exc_info=True)
        raise

    logger.info(f"✓ {len(arm_resources)} resource(s) defined in Bicep (scope: {deployment_scope})")
    return arm_resources, deployment_scope


def _fetch_live_state(resource_group: str, deployment_scope: str, arm_resources: list[dict]) -> list[dict]:
    """Query Resource Graph, then augment with cross-sub resources and Defender pricings.

    Cross-sub: a vending template may deploy resources into ANOTHER subscription
    (e.g. hub-side peering from a spoke template); the scanned sub can't see
    them, so each is fetched directly and merged so it's property-compared
    instead of false-flagged missing.

    Extension names: diagnostic settings are qualified to '{scope}/{name}' to
    align with the live expansion.

    Defender: pricings are fetched only when the template declares them (every
    sub has a Free-tier row for every plan - undeclared ones would flood extras).
    """
    logger.info("Step 2: Querying live Azure state via Resource Graph...")
    try:
        scope = "subscription" if deployment_scope == "subscription" else "resource_group"
        if scope == "subscription":
            logger.debug("Querying at subscription scope...")
        live_resources = get_live_state(resource_group=resource_group, scope=scope)
    except ValueError as e:
        logger.error(f"Missing subscription ID: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to query Azure: {e}", exc_info=True)
        logger.info("Ensure you're logged in: az login")
        raise

    logger.info(f"✓ {len(live_resources)} resource(s) deployed in Azure (scope: {deployment_scope})")

    live_resources.extend(fetch_cross_subscription_resources(arm_resources))
    qualify_extension_resource_names(arm_resources)
    live_resources.extend(fetch_declared_defender_pricings(
        arm_resources, os.environ.get("AZURE_SUBSCRIPTION_ID")
    ))
    return live_resources


def _load_ignore_patterns(bicep_file: str) -> IgnorePatternList:
    """Find and load .drift-ignore from the bicep repo root, cwd, or parent dir."""
    logger.info("Step 3: Loading ignore patterns...")
    bicep_dir = Path(bicep_file).parent.parent  # bicep/main.bicep → repo root
    for path in (bicep_dir / ".drift-ignore", Path(".drift-ignore"), Path("../.drift-ignore")):
        if path.exists():
            logger.debug(f"Found .drift-ignore at: {path.resolve()}")
            ignore_patterns = IgnorePatternList.from_file(path)
            if ignore_patterns.patterns:
                ignore_patterns.log_summary()
            return ignore_patterns
    logger.debug("No ignore patterns found")
    return IgnorePatternList([])


def _diff_states(arm_resources: list[dict], live_resources: list[dict],
                 ignore_patterns: IgnorePatternList) -> list[ResourceDrift]:
    """Run the base template diff."""
    logger.info("Step 4: Diffing desired vs actual...")
    try:
        return diff_states(arm_resources, live_resources, ignore_patterns=ignore_patterns)
    except Exception as e:
        logger.error(f"Failed to diff states: {e}", exc_info=True)
        raise


def _to_resource_drifts(drift_dicts: list[dict]) -> list[ResourceDrift]:
    """Convert sidecar-comparator dicts into ResourceDrift records."""
    return [
        ResourceDrift(
            resource_type=d["type"],
            resource_name=d["name"],
            drift_type=d["drift_type"],
            details=d.get("details", {}),
        )
        for d in drift_dicts
    ]


def _apply_sidecar_ignore(drift_dicts: list[dict], ignore_patterns: IgnorePatternList,
                          label: str) -> list[dict]:
    """Filter a sidecar's drift list through ignore patterns and log the count."""
    if not (ignore_patterns.patterns and drift_dicts):
        return drift_dicts
    filtered, ignored = ignore_patterns.filter_drifts(drift_dicts)
    if ignored:
        logger.info(f"Ignoring {len(ignored)} {label} drift(s) per ignore patterns")
    return filtered


def _run_rbac_sidecar(arm_resources: list[dict], live_resources: list[dict],
                      resource_group: str, deployment_scope: str,
                      ignore_patterns: IgnorePatternList, drifts: list[ResourceDrift]) -> None:
    """Step 4b: RBAC role-assignment drift.

    Assignments are invisible to the normal pipeline (not in Resource Graph's
    Resources table; guid(...) names skipped by the comparator), so they get
    their own identity-based compare. Disable with INCLUDE_ROLE_ASSIGNMENTS=false.
    """
    if not rbac_enabled():
        return
    logger.info("Step 4b: Checking RBAC role assignments...")
    try:
        live_assignments = fetch_role_assignments(
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
            scope=deployment_scope if deployment_scope == "subscription" else "resource_group",
        )
        rbac_drift_dicts = compare_role_assignments(
            arm_resources, live_assignments,
            deployed_principals=collect_managed_identity_principals(live_resources),
        )
        rbac_drift_dicts = _apply_sidecar_ignore(rbac_drift_dicts, ignore_patterns, "RBAC")
        drifts.extend(_to_resource_drifts(rbac_drift_dicts))
    except Exception as e:
        logger.warning(f"RBAC drift check failed (continuing without it): {e}")


def _run_policy_sidecar(arm_resources: list[dict], resource_group: str,
                        deployment_scope: str, ignore_patterns: IgnorePatternList,
                        drifts: list[ResourceDrift]) -> None:
    """Step 4c: Policy assignment/exemption drift - the governance twin of 4b.

    policyresources table; identity-based matching; out-of-band exemptions are
    audit-critical. Disable with INCLUDE_POLICY_ASSIGNMENTS=false.
    """
    if not policy_drift_enabled():
        return
    logger.info("Step 4c: Checking policy assignments and exemptions...")
    try:
        live_pol, live_exemptions = fetch_policy_resources(
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
            scope=deployment_scope if deployment_scope == "subscription" else "resource_group",
        )
        policy_drift_dicts = compare_policy_resources(arm_resources, live_pol, live_exemptions)
        policy_drift_dicts = _apply_sidecar_ignore(policy_drift_dicts, ignore_patterns, "policy")
        drifts.extend(_to_resource_drifts(policy_drift_dicts))
    except Exception as e:
        logger.warning(f"Policy drift check failed (continuing without it): {e}")


def _run_stack_sidecar(live_resources: list[dict], resource_group: str,
                       deployment_scope: str, ignore_patterns: IgnorePatternList,
                       drifts: list[ResourceDrift]) -> None:
    """Step 4d: Deployment stack drift. OPT-IN.

    Runs only when the check's LZ config declares a `deployment_stack`, because
    a stack's enforcement posture has no template to diff against and must be
    declared. Two payoffs: the stack's own denySettings/actionOnUnmanage/health,
    and its managed list as an AUTHORITATIVE ownership oracle replacing the
    RG-boundary guess.
    """
    if not stack_drift_enabled():
        return
    logger.info("Step 4d: Checking deployment stack...")
    try:
        stack_cfg = load_stack_config()
        stack_scope = deployment_scope if deployment_scope == "subscription" else "resource_group"
        live_stack, token = fetch_deployment_stack(
            stack_cfg,
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
        )
        stack_drift_dicts = compare_deployment_stack(
            stack_cfg,
            live_stack,
            live_resources,
            subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            resource_group=resource_group,
            scope=stack_scope,
            token=token,
        )
        # A stack-managed resource the template also declares would be reported
        # missing twice; the template compare owns that finding.
        stack_drift_dicts = dedupe_against(stack_drift_dicts, drifts)
        stack_drift_dicts = _apply_sidecar_ignore(stack_drift_dicts, ignore_patterns, "stack")
        drifts.extend(_to_resource_drifts(stack_drift_dicts))
        annotate_stack_ownership(drifts, live_stack, live_resources)
    except Exception as e:
        logger.warning(f"Deployment stack check failed (continuing without it): {e}")


def _save_phase1_report(bicep_file: str, resource_group: str,
                        arm_resources: list[dict], live_resources: list[dict],
                        drifts: list[ResourceDrift]) -> None:
    """Persist the raw Phase 1 report.

    A subscription-scope scan may use '*' or a glob selector (e.g. 'prefix-*');
    use a filesystem-safe label for the file. Secret-bearing property values
    are scrubbed before write - property comparison already ignores write-only
    secrets, this covers the raw dump.
    """
    try:
        label = rg_label(resource_group)
        output_file = Path(f"reports/{label}-drift.json")
        output_file.parent.mkdir(exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({
                "resource_group": label,
                "bicep_file": bicep_file,
                "arm_resources": redact_secrets(arm_resources),
                "live_resources": redact_secrets(live_resources),
                "drift_count": len(drifts),
                "drifts": [
                    {
                        "type": d.resource_type,
                        "name": d.resource_name,
                        "drift_type": d.drift_type,
                        "details": d.details,
                    }
                    for d in drifts
                ],
            }, f, indent=2, default=str)
        logger.info(f"✓ Raw output saved to: {output_file}")
    except Exception as e:
        logger.warning(f"Could not write report: {e}")


def run(bicep_file: str, resource_group: str):
    """Phase 1 orchestrator: compile → live state → diff → sidecars → persist."""
    logger.info(f"Bicep Drift Check — {bicep_file} (resource group: {resource_group})")

    param_overrides = _resolve_parameter_overrides(bicep_file, resource_group)
    arm_resources, deployment_scope = _compile_and_extract(bicep_file, param_overrides)
    live_resources = _fetch_live_state(resource_group, deployment_scope, arm_resources)
    ignore_patterns = _load_ignore_patterns(bicep_file)
    drifts = _diff_states(arm_resources, live_resources, ignore_patterns)

    _run_rbac_sidecar(arm_resources, live_resources, resource_group, deployment_scope,
                      ignore_patterns, drifts)
    _run_policy_sidecar(arm_resources, resource_group, deployment_scope,
                        ignore_patterns, drifts)
    _run_stack_sidecar(live_resources, resource_group, deployment_scope,
                       ignore_patterns, drifts)

    logger.info("Drift Report Summary")
    logger.info(format_drift_report(drifts, resource_group))
    _save_phase1_report(bicep_file, resource_group, arm_resources, live_resources, drifts)


def main():
    # Initialize logging (DRIFT_LOG_LEVEL overrides the default)
    from tools.config import LOG_LEVEL, validate_config
    setup_logging(level=LOG_LEVEL)
    for warning in validate_config():
        logger.warning(f"Config: {warning}")

    if len(sys.argv) < 3:
        logger.error("Usage: python run_drift_check.py <bicep-file> <resource-group>")
        sys.exit(1)

    bicep_file = sys.argv[1]
    resource_group = sys.argv[2]

    if not Path(bicep_file).exists():
        logger.error(f"Bicep file not found: {bicep_file}")
        sys.exit(1)

    if not bicep_file.endswith(".bicep"):
        logger.error(f"Expected .bicep file, got: {bicep_file}")
        sys.exit(1)

    try:
        run(bicep_file, resource_group)
    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Value error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
