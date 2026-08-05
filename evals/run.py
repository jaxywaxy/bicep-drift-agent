"""
evals/run.py

Run every fixture through the configured LLM provider and check what it wrote.

    python3 -m evals.run                          # current provider
    DRIFT_LLM_PROVIDER=azure_openai python3 -m evals.run
    python3 -m evals.run --dry-run                # no API call; checks only

Exits non-zero on any violation, so it can gate a provider change.

This exists because nothing else looks at the analysis OUTPUT. Without it the
only quality signal is a human reading one report, which does not scale to two
providers and is how a provider would produce quietly worse analysis for months.

It makes REAL API calls and costs real money (~36.9K tokens per fixture on the
recorded payload), so it is deliberately not part of the unit suite. The
judgement it applies is - see tests/test_narrative_checks.py.
"""

import argparse
import json
import pathlib
import sys

from dotenv import load_dotenv

from evals.checks import run_all_checks

# Same as analyze_drift.py: the key lives in .env locally and in CI secrets.
# Without this the runner reports a provider error on every fixture and looks
# like a narrative failure to anyone reading only the exit code.
load_dotenv()

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _to_report(raw: dict):
    from tools.models import Drift, DriftReport
    drifts = []
    for d in raw.get("drifts") or []:
        drifts.append(Drift(
            resource_type=d.get("type", ""),
            resource_name=d.get("name", ""),
            drift_type=d.get("drift_type", ""),
            severity=str(((d.get("change_origin") or {}).get("severity")) or "info"),
            details=d.get("details") or {},
            resource_id=(d.get("lifecycle") or {}).get("resource_id"),
            change_origin=d.get("change_origin"),
        ))
    return DriftReport(
        bicep_file=raw.get("bicep_file", ""),
        resource_group=raw.get("resource_group", ""),
        drifts=drifts,
    )


def _current_provider():
    """The provider this run will actually use.

    Reported up front because the failure that cost two rounds was believing
    Azure was in play while Anthropic was: GitHub repo VARIABLES exist only
    inside Actions, so a local shell silently falls back to the default.
    """
    from agent.llm import get_provider
    return get_provider()


def _describe_failure(provider, exc: Exception) -> str:
    """Plain-language cause, asked of the provider - the same explainers the
    pipeline uses. The raw error is kept when nothing can explain it, rather
    than swallowed."""
    from orchestration.analysis import _explain_llm_failure
    name = getattr(provider, "name", "unknown")
    hint = _explain_llm_failure(provider, exc)
    detail = f"{hint} ({type(exc).__name__}: {exc})" if hint else f"{type(exc).__name__}: {exc}"
    return f"[provider: {name}] {detail}"


def _analyse(raw: dict) -> str:
    from agent.drift_agent import DriftAgent
    return DriftAgent().analyze_drift(_to_report(raw))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="skip the API call; check a canned string instead (wiring smoke test)")
    ap.add_argument("--fixture", help="run one fixture by filename stem")
    ap.add_argument("--report", help=(
        "check the agent_analysis ALREADY in a drift report, instead of calling "
        "the provider. Free, and the only way to check a narrative after the "
        "fact - e.g. the report a CI run just produced."))
    args = ap.parse_args(argv)

    if args.report:
        raw = json.loads(pathlib.Path(args.report).read_text())
        analysis = raw.get("agent_analysis") or ""
        if not analysis:
            print(f"{args.report} has no agent_analysis to check "
                  "(clean estate, or the LLM call was skipped)", file=sys.stderr)
            return 0
        print(f"\n=== {pathlib.Path(args.report).name} (recorded analysis) ===")
        total = 0
        for name, violations in run_all_checks(raw, analysis).items():
            label = name.replace("check_", "").replace("_", " ")
            if violations:
                total += len(violations)
                print(f"  FAIL  {label}")
                for v in violations:
                    print(f"          {v}")
            else:
                print(f"  ok    {label}")
        print(f"\n{total} violation(s)" if total else "\nNo violations.")
        return 1 if total else 0

    paths = sorted(FIXTURES.glob("*.json"))
    if args.fixture:
        paths = [p for p in paths if p.stem == args.fixture]
    if not paths:
        print("no fixtures found", file=sys.stderr)
        return 2

    total = 0
    for path in paths:
        raw = json.loads(path.read_text())
        print(f"\n=== {path.stem} ===")
        if raw.get("_what_this_pins"):
            print(f"  pins: {raw['_what_this_pins']}")
        try:
            analysis = "(dry run - no analysis)" if args.dry_run else _analyse(raw)
        except Exception as e:
            # A provider failure is not a narrative violation; say which provider
            # and why, or the operator cannot tell a misconfiguration from a bad
            # analysis.
            try:
                provider = _current_provider()
            except Exception:
                provider = None
            print(f"  PROVIDER ERROR  {_describe_failure(provider, e)}")
            total += 1
            continue

        for name, violations in run_all_checks(raw, analysis).items():
            label = name.replace("check_", "").replace("_", " ")
            if violations:
                total += len(violations)
                print(f"  FAIL  {label}")
                for v in violations:
                    print(f"          {v}")
            else:
                print(f"  ok    {label}")

    print(f"\n{total} violation(s)" if total else "\nNo violations.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
