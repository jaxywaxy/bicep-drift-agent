"""
evals/checks.py

Mechanical assertions on the analysis TEXT. No LLM judges another LLM here -
every check below is a deterministic function of (report, analysis), which is
what makes "did provider B get worse?" answerable without a human reading
reports.

Each encodes a failure OBSERVED in a live report, in one of two scopes:

1. EVIDENCE - did the narrative contradict the data it was given. The original
   scope, and the one that matters most.
2. SHAPE - is the document the four-section report the prompt asks for, or has
   it drifted back into an exam script / a wall of repetition. Added after two
   rounds of tuning those rules by hand against a single report each time, which
   found real defects but only the ones somebody happened to notice.

Neither is a proxy for prose quality. Whether it READS well is not checkable and
is deliberately not attempted - a check nobody trusts gets disabled, and a
disabled check is worse than none because it looks like coverage. Shape is not
prose: heading text, section names and word counts are exact.
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
        # EVERY value in details, not a hand-listed subset of keys. The list was
        # created_by/principal_id/assignment_id, which missed
        # `role_definition_guid` - so an analysis correctly naming the custom
        # role it was shown got accused of inventing an identity. Caught against
        # the real 2026-08-06 subscription report. Whatever the report carries,
        # the narrative may cite; enumerating keys guarantees the next miss.
        for val in (row.get("details") or {}).values():
            if isinstance(val, (str, int)):
                actors.add(str(val).lower())
    # A guid the report carries INSIDE a resource id is still an identifier the
    # report carries. Without this, `_known_actors` holds the full ARM path
    # while `_GUID` extracts the bare guid, they never match, and an analysis
    # quoting a resource id verbatim is accused of inventing an actor. A check
    # that fires on correct output gets muted, and a muted check still looks
    # like coverage.
    for value in list(actors):
        actors.update(m.lower() for m in _GUID.findall(value))
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


# --- shape ---------------------------------------------------------------
# The prompt fixes four `##` sections. A heading is matched by the distinctive
# PHRASE, not equality, so a subtitle ("## Caveats, confidence and data quality")
# passes while a question heading does not. "remediation plan" is deliberately
# the whole phrase: "## Which should be remediated by redeploying Bicep?" and
# "## ... Azure Policy remediation or exception tracking?" both contain
# "remediat" and both are exactly what this check exists to catch.
_ALLOWED_SECTIONS = ("tl;dr", "priority findings", "remediation plan", "caveat")
_H2 = re.compile(r"^##(?!#)\s*(.+?)\s*$", re.M)
_H3 = re.compile(r"^###\s*(.+?)\s*$", re.M)
_FENCE = re.compile(r"```.*?```", re.S)
# A heading is a label a reader scans. The live failure was a 120-char ARM path.
_MAX_HEADING_CHARS = 90
_REMEDIATION_IN_FINDING = re.compile(
    r"^\s*[-*]?\s*\**\s*(immediate|recommended|suggested)\s+action\b", re.I | re.M)
_SIGN_OFFS = ("end of report", "end of analysis", "that concludes", "this concludes")
# Headroom over the prompt's 600-900 target: this fires on the pathological
# case, not on a report that ran slightly long. Fenced code is excluded, so
# writing a Bicep snippet inline - which the prompt REQUIRES - never costs here.
_BASE_WORD_BUDGET = 1200
_WORDS_PER_EXTRA_FINDING = 100
_BUDGET_FREE_FINDINGS = 6


def _actionable(report):
    return [r for r in _rows(report) if r.get("drift_type") not in _NOT_A_FINDING]


def _finding_blocks(analysis):
    """(heading, body) per `###` section - the unit the shape rules govern."""
    matches = list(_H3.finditer(analysis))
    return [
        (m.group(1), analysis[m.end(): matches[i + 1].start() if i + 1 < len(matches) else len(analysis)])
        for i, m in enumerate(matches)
    ]


def check_only_allowlisted_sections(report, analysis):
    """The four `##` sections are an allowlist.

    Live twice: the request's own question list was promoted to headings
    ("## Which findings are likely Azure-managed resources?"), which reads as an
    exam script and buries the plan among meta-questions nobody asked. It
    survived the first, softer wording of the rule.
    """
    return [
        f"section heading {h!r} is not one of the four allowed"
        for h in _H2.findall(analysis)
        if not any(a in h.lower() for a in _ALLOWED_SECTIONS)
    ]


def check_finding_headings_are_labels(report, analysis):
    """A finding heading names the resource; it is not the resource ID.

    Live: six headings were the full `/subscriptions/.../RoleAssignments/<guid>`,
    each followed by a `- Resource ID:` bullet repeating the identical string.
    """
    out = []
    for heading in _H3.findall(analysis):
        if "/subscriptions/" in heading or "/providers/" in heading:
            out.append(f"finding heading is a resource ID, not a label: {heading[:60]!r}...")
        elif len(heading) > _MAX_HEADING_CHARS:
            out.append(f"finding heading is {len(heading)} chars, over {_MAX_HEADING_CHARS}: {heading[:60]!r}...")
    return out


def check_findings_do_not_carry_remediation(report, analysis):
    """A finding states the problem; the plan states the fix, once.

    Live: every finding ended "Immediate action: verify this principal", the
    plan said verify, and a third section said verify again.
    """
    return [
        f"finding {heading[:50]!r} carries its own remediation line"
        for heading, body in _finding_blocks(analysis)
        if _REMEDIATION_IN_FINDING.search(body)
    ]


def check_length_within_budget(report, analysis):
    """A correct analysis nobody finishes reading is worth nothing.

    Live: adding structure rules without a budget grew the report 27%
    (4,861 -> 6,195 output tokens) - the extra room went on restating the same
    four role assignments in four places.
    """
    words = len(_FENCE.sub(" ", analysis).split())
    budget = _BASE_WORD_BUDGET + _WORDS_PER_EXTRA_FINDING * max(
        0, len(_actionable(report)) - _BUDGET_FREE_FINDINGS)
    if words > budget:
        return [f"{words} words of prose against a {budget}-word budget"]
    return []


def check_no_sign_off(report, analysis):
    """The document ends at the last caveat. A sign-off is chat residue."""
    tail = analysis[-200:].lower()
    return [f"ends with a sign-off ({s!r})" for s in _SIGN_OFFS if s in tail]


CHECKS = (
    check_no_fabricated_actor,
    check_no_unearned_attribution,
    check_critical_findings_are_mentioned,
    check_tldr_does_not_soften_what_the_body_confirms,
    check_does_not_over_unify_across_time,
    check_only_allowlisted_sections,
    check_finding_headings_are_labels,
    check_findings_do_not_carry_remediation,
    check_length_within_budget,
    check_no_sign_off,
)


def run_all_checks(report, analysis) -> dict:
    """{check_name: [violations]} - every check runs, so one failure does not
    mask the rest."""
    return {c.__name__: c(report, analysis) for c in CHECKS}
