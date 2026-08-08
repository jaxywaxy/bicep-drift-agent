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

import json
import re
from datetime import datetime

# Deliberately narrow: an email, or a bare GUID. Broad "name-like" extraction
# produced false positives on ordinary prose in every shape tried.
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)

_SOFTENERS = ("benign", "no action", "cosmetic", "nothing to do", "safe to ignore",
              "no remediation", "expected and safe")
# Sentences that DENY a claim rather than make it. Anthropic wrote "the PE has a
# timestamp, the vault has none, so I cannot claim a single event" - a textbook
# refusal to over-unify - and the phrase matcher failed it for containing the
# words. Punishing the exact caution the rule asks for is the fastest way to get
# a check muted, so the denial is removed before matching.
_NEGATED_CLAIM = re.compile(
    r"[^.\n]*\b(?:cannot|can't|could not|couldn't|do not|don't|does not|doesn't|"
    r"no evidence|not|never|unverified|unable to)\b[^.\n]*[.\n]", re.I)


def _strip_negated_claims(text: str) -> str:
    """Drop sentences that negate, so a refusal is not read as an assertion."""
    return _NEGATED_CLAIM.sub(" ", text)


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
    """Every identifier the report carries, wherever it carries it.

    Deliberately the WHOLE report and not a walk of chosen fields. That approach
    has now been wrong three times, each fix enumerating one more key while the
    next real report found the next gap: `role_definition_guid` missing from a
    hand-listed `details` subset, then guids buried inside resource ids, then
    the subscription guid in `lifecycle.resource_id` - which is in all 42 rows
    of `policy_enforced_estate` and got a correct analysis accused of inventing
    an identity.

    The question here is "did the narrative name an identity the report does not
    contain?", so the only honest denominator is the report. Anything narrower
    is a guess about where identities live, and this check firing on correct
    output is worse than it not existing - a check people learn to ignore still
    looks like coverage.

    Extracting the same two shapes the narrative side extracts keeps the
    comparison symmetric; misusing an identity that IS present is a different
    failure, and `check_no_unearned_attribution` owns it.
    """
    blob = json.dumps(report)
    return ({m.lower() for m in _GUID.findall(blob)}
            | {m.lower() for m in _EMAIL.findall(blob)})


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


def _identifies(row) -> list[str]:
    """Strings any one of which proves the narrative named this finding.

    A sidecar comparator has no ARM name to use, so it synthesises one:
    `Owner -> ServicePrincipal:8edd43ce-...`. No readable sentence quotes that
    verbatim, and requiring it failed BOTH providers on a report where each had
    described the grant properly, by role and principal. Accept any identifier
    that unambiguously picks the finding out instead.
    """
    name = str(row.get("name") or "")
    details = row.get("details") or {}
    candidates = [name]
    for key in ("principal_id", "assignment_id", "role_definition_guid"):
        if details.get(key):
            candidates.append(str(details[key]))
    # The assignment's own guid, so quoting `RoleAssignments/<guid>` rather than
    # the full ARM path still counts as naming it.
    if details.get("assignment_id"):
        candidates.append(str(details["assignment_id"]).rsplit("/", 1)[-1])
    # The bare guid out of a synthetic name, for the same reason.
    candidates += _GUID.findall(name)
    return [c for c in candidates if c]


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
        identifiers = _identifies(row)
        if identifiers and not any(i.lower() in low for i in identifiers):
            missing.append(f"{sev} finding {str(row.get('name'))!r} is never mentioned")
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
    low = _strip_negated_claims(analysis).lower()
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
# A whole line that IS a command - the shape that renders as prose when left
# unfenced. An inline mention inside a sentence never starts the line, so it
# does not match; a `- ` or `* ` bullet marker is stripped first.
_BARE_COMMAND = re.compile(
    r"^[ \t]*(?:[-*]\s+)?(?:az|bicep|terraform|kubectl|pwsh)\s+\S.*$", re.M)
_SIGN_OFFS = ("end of report", "end of analysis", "that concludes", "this concludes")
# An INDENTED ordered marker - `  1.` or `   1)` - i.e. a step inside a step.
# Matched only within the plan section, and never inside a fenced block.
_NESTED_ORDERED = re.compile(r"^[ \t]+\d+[.)]\s+\S", re.M)
# Headroom over the prompt's 600-900 target: this fires on the pathological
# case, not on a report that ran slightly long. Fenced code is excluded, so
# writing a Bicep snippet inline - which the prompt REQUIRES - never costs here.
_BASE_WORD_BUDGET = 1200
_WORDS_PER_EXTRA_FINDING = 100
_BUDGET_FREE_FINDINGS = 6


def _actionable(report):
    return [r for r in _rows(report) if r.get("drift_type") not in _NOT_A_FINDING]


def _plan_section(analysis):
    """Text under the `## Remediation plan` heading, up to the next `##`."""
    m = re.search(r"^##(?!#)\s*.*remediation plan.*$", analysis, re.M | re.I)
    if not m:
        return ""
    rest = analysis[m.end():]
    nxt = re.search(r"^##(?!#)", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


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


def _expected_stories(report):
    """How many distinct CAUSES the report actually contains.

    Rows sharing one `policy_name` are one cause however many resources they
    touch; everything else counts individually.
    """
    policies, loose = set(), 0
    for row in _actionable(report):
        name = ((row.get("change_origin") or {}).get("policy_name")) or ""
        if name:
            policies.add(name)
        else:
            loose += 1
    return len(policies) + loose


# Slack over the cause count: a report may legitimately add a heading the rows do
# not imply - the previous provider wrote "### No composed/interacting drift".
# Generous on purpose; this must only fire on real sprawl.
_STORY_HEADING_SLACK = 3


def check_one_story_is_one_finding(report, analysis):
    """N resources drifted by ONE cause is ONE finding, not N.

    The counterexample is the thing to protect: 39 resources whose tag was
    rewritten by a single policy Modify effect, reported as one finding - "LOW
    x 39, one story, many resources" - which IS the insight. Thirty-nine
    headings repeating one sentence would be strictly worse.

    No other check can see this. The word budget scales with the finding count,
    so 39 near-identical headings sit comfortably inside it.
    """
    expected = _expected_stories(report)
    if not expected:
        return []
    headings = len(_H3.findall(analysis))
    if headings > expected + _STORY_HEADING_SLACK:
        return [f"{headings} finding headings for {expected} distinct cause(s); "
                f"rows sharing one cause must be reported as one finding"]
    return []


def check_commands_are_fenced(report, analysis):
    """A command is only readable if it renders as a framed monospace block.

    Live: the plan wrote `az role assignment show ...` as an indented plain-text
    line under a `- Command:` bullet. python-markdown folded the whole step -
    command, bullets and all - into one <li> of proportional prose. Nothing to
    scan, nothing to copy.

    Whether the fence is at column 0 is `check_fences_start_at_column_zero`'s
    job - this one only asks whether a command was fenced at all.
    """
    outside = _FENCE.sub(" ", analysis)
    return [f"unfenced command line: {m.group(0).strip()[:60]!r}"
            for m in _BARE_COMMAND.finditer(outside)]


def check_plan_is_flat(report, analysis):
    """The remediation plan is a list an operator works top to bottom.

    Live: the round-2 rules capped bullets per FINDING and the plan blew the
    budget anyway - six items with five nested sub-steps each. Nesting is also
    where duplication hides, because each branch re-pastes the same command.

    Only the plan section is inspected: a nested list under a finding is already
    governed by the six-bullet cap, and code blocks legitimately indent.
    """
    plan = _plan_section(analysis)
    if not plan:
        return []
    nested = _NESTED_ORDERED.findall(_FENCE.sub(" ", plan))
    if nested:
        return [f"remediation plan has {len(nested)} nested sub-step(s); it must be flat"]
    return []


_CMD_LINE = re.compile(r"^\s*(az [^\n]+)$", re.M)


def _command_shape(cmd: str) -> str:
    """A command reduced to its verb and FLAGS, with argument values dropped.

    `az role assignment delete --ids /subscriptions/.../A` and the same line for
    B share a shape. That is the duplication worth catching: one invocation with
    the ids listed under it says the same thing in a fraction of the space.
    `what-if` and `create` keep different shapes, so a legitimate pair survives.
    """
    tokens, out, seen_flag = cmd.split(), [], False
    for token in tokens:
        if token.startswith("-"):
            seen_flag = True
            out.append(token.split("=", 1)[0])
        elif not seen_flag:
            out.append(token)          # still in the verb ('az role assignment delete')
    return " ".join(out)


def check_commands_are_not_repeated(report, analysis):
    """One invocation per command, with the ids listed under it.

    The prompt has said this since round 2 and nothing measured it. On the live
    prod report gpt-5-mini emitted 21 commands across 8 distinct verbs - `az
    role assignment ...` seven times, `az resource show` four - where Anthropic
    used 5. That is where the extra length went: the findings were actually
    LEANER than Anthropic's, and the remediation plan carried 31 lines of
    near-identical shell against 12.
    """
    shapes = {}
    for cmd in _CMD_LINE.findall(analysis):
        shapes.setdefault(_command_shape(" ".join(cmd.split())), []).append(cmd)
    return [
        f"`{shape}` written {len(uses)} times - give it once and list the arguments under it"
        for shape, uses in shapes.items() if len(uses) > 1
    ]


def check_does_not_delete_the_deployer(report, analysis):
    """Never hand someone a command that revokes the pipeline's own access.

    Observed live: three subscription Owner grants were listed for
    `az role assignment delete`, one of them the service principal the SAME
    report credits with five `authorized_deployment` changes. Running it breaks
    every future deploy - including the remediation proposed two steps earlier.

    Flagging a standing privileged grant is right; a bare delete command for the
    deployer is not. This checks only the command, so "narrow this role" or
    "move the grant into Bicep" still passes.
    """
    deployers = {
        str((row.get("change_origin") or {}).get("changed_by") or "").lower()
        for row in _rows(report)
        if (row.get("change_origin") or {}).get("origin") == "authorized_deployment"
    } - {""}
    if not deployers:
        return []

    # Every identifier that would name the deployer's grant in a command.
    targets = {}
    for row in _rows(report):
        details = row.get("details") or {}
        principal = str(details.get("principal_id") or "").lower()
        if principal and principal in deployers:
            for ident in (details.get("assignment_id"), principal, row.get("name")):
                if ident:
                    targets[str(ident).lower()] = principal
    if not targets:
        return []

    out = []
    for line in analysis.splitlines():
        low = line.lower()
        if "role assignment delete" not in low:
            continue
        for ident, principal in targets.items():
            if ident in low:
                out.append(
                    f"proposes deleting the role assignment of {principal!r}, which this "
                    f"report attributes authorized deployments to - that is the pipeline")
                break
    return out


def check_snippets_use_the_declared_location(report, analysis):
    """A snippet is applied, so a guessed region is a defect, not a gap.

    Observed live: replacement Bicep for an australiaeast estate hardcoded
    `location: 'eastus'` twice, in a report that names the real location on
    every declared resource.
    """
    declared = {
        str(res.get("location") or "").lower()
        for res in report.get("arm_resources") or []
    } - {"", "unknown", "none"}
    if not declared:
        return []
    return [
        f"snippet uses location {loc!r}, but the template declares {sorted(declared)}"
        for loc in {m.group(1).lower() for m in re.finditer(r"location:\s*'([^']+)'", analysis)}
        if loc not in declared
    ]


def check_fences_start_at_column_zero(report, analysis):
    """A fence indented inside a list item is not a code block.

    python-markdown treats it as an inline code span, so the framed monospace
    block a reader scans and copies becomes a run of proportional text mid
    sentence. The prompt has required column 0 since round 2, and this went
    unchecked because `check_commands_are_fenced` only asks whether backticks
    exist - it passes on an indented fence.

    That gap was not theoretical. On the first live prod landing-zone report
    ALL 22 fences were indented three or five spaces, every check passed, and
    the rendered HTML contained zero <pre> blocks and eleven inline spans - the
    exact regression the rule exists to prevent, invisible to the eval.

    A rule that is stated but unchecked is worth about as much as one that is
    checked but unstated, which is the same lesson from the other direction.
    """
    return [
        f"fence indented {len(m.group(1))} spaces at line {analysis[:m.start()].count(chr(10)) + 1}"
        f" - renders as an inline span, not a code block"
        for m in re.finditer(r"^([ \t]+)```", analysis, re.M)
    ]


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
    check_plan_is_flat,
    check_commands_are_fenced,
    check_fences_start_at_column_zero,
    check_commands_are_not_repeated,
    check_does_not_delete_the_deployer,
    check_snippets_use_the_declared_location,
    check_one_story_is_one_finding,
)


def run_all_checks(report, analysis) -> dict:
    """{check_name: [violations]} - every check runs, so one failure does not
    mask the rest."""
    return {c.__name__: c(report, analysis) for c in CHECKS}
