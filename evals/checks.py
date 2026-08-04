"""
evals/checks.py

Mechanical assertions on the analysis TEXT. No LLM judges another LLM here -
every check below is a deterministic function of (report, analysis), which is
what makes "did provider B get worse?" answerable without a human reading
reports.

Each encodes a failure OBSERVED in a live report. None is a proxy for prose
quality: the honest scope is *did the narrative contradict the evidence it was
given*, and that is checkable. Whether it reads well is not, and is deliberately
not attempted - a check nobody trusts gets disabled, and a disabled check is
worse than none because it looks like coverage.
"""

import re
from datetime import datetime

# Deliberately narrow: an email, or a bare GUID. Broad "name-like" extraction
# produced false positives on ordinary prose in every shape tried.
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)

_SOFTENERS = ("benign", "no action", "cosmetic", "nothing to do", "safe to ignore",
              "no remediation", "expected and safe")
_UNIFYING = ("single event", "one event", "a single operation", "one action",
             "one operator action", "coherent single")
_SEPARATING = ("distinct operation", "two operation", "separate operation",
               "more than one operation", "distinct action", "apart")
# Two ~30s-apart deletions ARE one cascade; 40 minutes apart are not. The live
# examples sit either side of this, and nothing observed falls near it.
_ONE_EVENT_WINDOW_SECONDS = 5 * 60


def _rows(report):
    return report.get("drifts") or []


def _known_actors(report):
    actors = set()
    for row in _rows(report):
        co = row.get("change_origin") or {}
        if co.get("changed_by"):
            actors.add(str(co["changed_by"]).lower())
        for ev in (row.get("lifecycle") or {}).get("events") or []:
            if ev.get("actor"):
                actors.add(str(ev["actor"]).lower())
        for key in ("created_by", "principal_id", "assignment_id"):
            val = (row.get("details") or {}).get(key)
            if val:
                actors.add(str(val).lower())
    return actors


def check_no_fabricated_actor(report, analysis):
    """No identity may appear in the narrative that is absent from the report.

    Naming someone the evidence does not name is the worst failure available to
    a tool people act on - it is an accusation the data does not support.
    """
    known = _known_actors(report)
    seen = {m.lower() for m in _EMAIL.findall(analysis)} | {m.lower() for m in _GUID.findall(analysis)}
    return [f"names {a!r}, which appears nowhere in the report" for a in sorted(seen - known)]


def check_no_unearned_attribution(report, analysis):
    """When the report attributes NOTHING, the narrative may not name a culprit.

    Live 2026-08-03: attribution was dead and every row read `origin: unknown`.
    A narrative naming someone anyway would have been confidently wrong.
    """
    rows = _rows(report)
    if not rows or _known_actors(report):
        return []
    named = _EMAIL.findall(analysis) + _GUID.findall(analysis)
    if named:
        return [f"report attributes nothing, but the analysis names {sorted(set(named))}"]
    # Prose attribution without an identifier - "changed by the platform team".
    if re.search(r"\bchanged by\b|\bdeleted by\b|\bmodified by\b|\bcreated by\b", analysis, re.I):
        return ["report attributes nothing, but the analysis asserts who acted"]
    return []


# Reconciled rows are NOT findings. A `matched_unresolvable` resource exists in
# Azure and was matched to its declaration; it carries a severity only because
# its creation was out of band, and the pipeline excludes it from what the agent
# is asked to analyse. Demanding the narrative mention it fires on correct
# output - caught against a real analysis 2026-08-04.
_NOT_A_FINDING = {"matched_unresolvable"}


def check_critical_findings_are_mentioned(report, analysis):
    """A critical finding the narrative never names will not be acted on."""
    low = analysis.lower()
    missing = []
    for row in _rows(report):
        if row.get("drift_type") in _NOT_A_FINDING:
            continue
        sev = str(((row.get("change_origin") or {}).get("severity") or "")).lower()
        if sev not in ("critical", "high"):
            continue
        name = str(row.get("name") or "")
        if name and name.lower() not in low:
            missing.append(f"{sev} finding {name!r} is never mentioned")
    return missing


def check_tldr_does_not_soften_what_the_body_confirms(report, analysis):
    """The softening line is the one a busy reader acts on without scrolling.

    Observed live: 34 findings called 'benign' in the TL;DR while the body said
    'none are benign'.
    """
    has_severe = any(
        str(((r.get("change_origin") or {}).get("severity") or "")).lower() in ("critical", "high")
        for r in _rows(report)
    )
    if not has_severe:
        return []
    head = analysis[:600].lower()
    hits = [w for w in _SOFTENERS if w in head]
    return ([f"TL;DR says {hits!r} while the report holds critical/high findings"] if hits else [])


def _event_times(report):
    times = []
    for row in _rows(report):
        for ev in (row.get("lifecycle") or {}).get("events") or []:
            ts = ev.get("timestamp")
            if not ts:
                continue
            try:
                times.append(datetime.fromisoformat(str(ts).replace("Z", "+00:00")))
            except ValueError:
                continue
    return times


def check_does_not_over_unify_across_time(report, analysis):
    """Calling a wide time span 'a single event' conceals that someone acted
    more than once - usually the fact the reader needed (#365)."""
    times = _event_times(report)
    if len(times) < 2:
        return []
    span = (max(times) - min(times)).total_seconds()
    if span <= _ONE_EVENT_WINDOW_SECONDS:
        return []
    low = analysis.lower()
    if any(p in low for p in _UNIFYING) and not any(p in low for p in _SEPARATING):
        return [f"calls a {int(span // 60)}-minute span a single event"]
    return []


CHECKS = (
    check_no_fabricated_actor,
    check_no_unearned_attribution,
    check_critical_findings_are_mentioned,
    check_tldr_does_not_soften_what_the_body_confirms,
    check_does_not_over_unify_across_time,
)


def run_all_checks(report, analysis) -> dict:
    """{check_name: [violations]} - every check runs, so one failure does not
    mask the rest."""
    return {c.__name__: c(report, analysis) for c in CHECKS}
