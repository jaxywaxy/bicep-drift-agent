"""
orchestration/analysis.py

The optional Claude analysis stage: run the agent over the reconciled drift when
ANTHROPIC_API_KEY is set, else write a synthetic "no drift" / estate summary. This
is by far the most expensive step, so it is skipped for clean estates - every
deterministic phase still runs without it (Claude is optional).
"""

from orchestration.reporting import _drift_type_counts
from tools.logger import get_logger
from tools.models import Drift, DriftReport

logger = get_logger(__name__)


def _clean_estate_summary(report_data: dict, reconciled: int) -> str:
    """The analysis narrative for a scan with no actionable drift, without Claude.

    Carries the same information Claude's clean-run narrative did (it opened
    "**No drift detected.**" and restated the counts) - all of which is already
    known deterministically once drift_count is 0.
    """
    lines = [
        "# Bicep Drift Analysis",
        "",
        "## TL;DR",
        "",
        f"**No drift detected.** `{report_data.get('resource_group', 'unknown')}` matches "
        f"`{report_data.get('bicep_file', 'the template')}`.",
        "",
        "- **Total drift findings: 0**",
        "- **Blocking drift: None**",
    ]
    if reconciled:
        lines.append(
            f"- **Resources reconciled: {reconciled}** (runtime-named resources matched "
            "to their deployed counterparts - informational, not drift)"
        )
    ignored = len(report_data.get("ignored_drifts") or [])
    if ignored:
        lines.append(f"- **Suppressed by ignore rules: {ignored}**")
    lines += [
        "",
        "No action required.",
        "",
        "_Generated deterministically: with no actionable drift there is nothing to "
        "analyse, so the Claude analysis call is skipped._",
    ]
    return "\n".join(lines)


def _explain_llm_failure(provider, exc: Exception) -> str:
    """Plain-language cause for an LLM failure, asked of the PROVIDER.

    Surfacing the common operational failures (exhausted credit, bad key) is
    worth doing, but the remediation is vendor-specific - so the vendor supplies
    it. A provider with no explainer, or an error it does not recognise, yields
    the generic message rather than another vendor's advice.
    """
    explain = getattr(provider, "explain_error", None)
    if explain is not None:
        try:
            hint = explain(exc)
        except Exception:  # an explainer must never replace the real failure
            hint = None
        if hint:
            return hint
    return "LLM analysis unavailable this run"


def _run_claude_analysis(agent, report_data: dict):
    """Build the DriftReport and, if an agent is available, run Claude analysis.

    Returns the analysis text (also stored in report_data['agent_analysis']), or
    None when no API key is configured OR the Claude call fails. A Claude failure
    is NON-FATAL and swallowed here: the deterministic pipeline (smart matching,
    ignore filtering, property drift, lifecycle) has already reconciled the
    report, and the caller must still persist THAT - re-raising aborted Phase 2
    before the persist and shipped the raw, un-reconciled Phase 1 dump (every
    uniqueString-named resource false-flagged extra_in_azure; seen live when the
    API key ran out of credit).
    """
    drifts = [
        Drift(
            resource_type=d["type"],
            resource_name=d["name"],
            drift_type=d["drift_type"],
            details=d.get("details"),
            # The report already carries the ARM id and attribution; thread them
            # to the agent so it reasons by id and cites the existing
            # change_origin instead of telling the user to pull Activity Logs.
            resource_id=(d.get("lifecycle") or {}).get("resource_id") or d.get("resource_id"),
            change_origin=d.get("change_origin"),
            lifecycle=d.get("lifecycle"),
        )
        for d in report_data.get("drifts", [])
    ]

    missing, extra, modified = _drift_type_counts(drifts)
    drift_report = DriftReport(
        bicep_file=report_data["bicep_file"],
        resource_group=report_data["resource_group"],
        drifts=drifts,
        total_missing=missing,
        total_extra=extra,
        total_modified=modified,
        # The agent attaches a short allowlist of sibling properties from these
        # (DriftAgent.LIVE_CONTEXT_PROPERTIES) to each finding. They are NOT
        # sent wholesale - a live payload runs to thousands of tokens. Without
        # them a finding carries only its changed paths, so the analysis hedged
        # "publicNetworkAccess not in the payload" and "I don't have
        # sku.capacity" about values sitting in this very report.
        live_resources=report_data.get("live_resources"),
        policy_assignments=report_data.get("policy_assignments"),
    )

    if not agent:
        return None

    # A clean estate is the COMMON case for a scheduled scan, and the analysis
    # call is BY FAR the most expensive thing in the run. Measured on a real
    # clean scan: 1 call, 1134 output tokens, $0.034, ~105s - i.e. ~75% of the
    # run's wall clock - spent having Claude narrate "No drift detected", which
    # drift_count already states deterministically. Skip the call and synthesise
    # the summary. (matched_unresolvable entries are runtime-named resources
    # reconciled to their deployed counterparts - informational, not drift; the
    # agent already excludes them from the analysis prompt.)
    actionable = [d for d in drifts if d.drift_type != "matched_unresolvable"]
    if not actionable:
        summary = _clean_estate_summary(report_data, reconciled=len(drifts) - len(actionable))
        report_data["agent_analysis"] = summary
        logger.info(
            "No actionable drift - skipping the Claude analysis call "
            "(deterministic summary instead)"
        )
        return summary

    logger.info(f"Calling {getattr(getattr(agent, 'provider', None), 'name', 'LLM')} for drift analysis...")
    try:
        agent_analysis = agent.analyze_drift(drift_report)
        logger.info("✓ LLM analysis completed")
        logger.info("DRIFT ANALYSIS")
        logger.info(agent_analysis)
        report_data["agent_analysis"] = agent_analysis
        return agent_analysis
    except Exception as e:
        hint = _explain_llm_failure(getattr(agent, "provider", None), e)
        logger.error(f"✗ LLM analysis failed ({type(e).__name__}): {hint}")
        logger.warning(
            "Continuing without AI analysis/recommendations - the deterministic "
            "drift report (smart matching, filtering, property drift) is unaffected."
        )
        print(f"[WARNING] Claude analysis skipped: {hint}")
        return None
