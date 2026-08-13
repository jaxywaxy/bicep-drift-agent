"""
Smart resource matching for unresolvable expressions.

Detects runtime-generated names in Bicep templates and attempts to match
them to deployed resources by type.
"""

import re
from collections import defaultdict

# The normalizer renders an unresolvable uniqueString() as a bracketed hex
# placeholder ('sqldrift[86c9cbf6]/driftdb') - no function-call marker left.
_PLACEHOLDER_RE = re.compile(r"\[[0-9a-fA-F]{6,}\]")

UNRESOLVABLE_FUNCTIONS = {
    'uniqueString',
    'copyIndex',
    'guid',
    'utcNow',
    'deployment',
    'reference',
    'listKeys',
    'take',
    'toLower',
    'concat',
    'format',
    'substring',
}


def detect_unresolvable_expressions(arm_template: dict) -> dict[str, list[str]]:
    """
    Detect resources with unresolvable runtime expressions in names.

    Returns:
        Dict mapping resource type to list of resource names with unresolvable expressions
    """
    unresolvable = defaultdict(list)

    resources = arm_template.get('resources', [])

    for resource in resources:
        resource_type = resource.get('type', '')
        resource_name = resource.get('name', '')

        # Check if name contains unresolvable functions
        if _has_unresolvable_expression(resource_name):
            unresolvable[resource_type].append(resource_name)

    return dict(unresolvable)


def _has_unresolvable_expression(name_str: str) -> bool:
    """Check if a string contains an unresolvable ARM function call.

    The analyzer partially resolves names, so an unresolvable name may keep its
    bracket form ([format(...)]) OR appear as a bare call
    (contosodevstgtake(uniqueString(resourceGroup().id), 6)). Detect either: a
    known function immediately followed by '(' is unresolvable.
    """
    if not isinstance(name_str, str):
        return False

    # Normalizer placeholder form ('aidrift[86c9cbf6]', 'sql[hex]/db'): the
    # function is gone but the name is still runtime-generated. Without this,
    # placeholder-named CHILDREN double-report as missing+extra (parents happen
    # to be rescued by the fuzzy-token matcher, slash-named children are not).
    if _PLACEHOLDER_RE.search(name_str):
        return True

    lowered = name_str.lower()
    for func in UNRESOLVABLE_FUNCTIONS:
        if f"{func.lower()}(" in lowered:
            return True

    return False


def names_plausibly_correspond(bicep_name: str, cand_name: str) -> bool:
    """Could a same-type live resource be this declared resource?

    Both arguments lowercase. THE one definition - three modules independently
    grew the same broken version of this test and all three shipped it:

        name_prefix = bicep_name.split("[")[0]      # 'sqldrift[hash]/driftdb'
        cand.startswith(name_prefix)                # -> 'sqldrift'

    `split("[")` stops at the first placeholder, so for a CHILD name shaped
    `parent[hash]/leaf` it discards the leaf entirely and the test collapses
    onto the parent - which every sibling shares by construction. Live
    2026-08-11: a deleted `sqldrift[hash]/driftdb` was reported missing under
    the name of its surviving sibling `sqldrift<hash>/master`, so the report
    asserted a resource that still exists was gone, and the real deletion was
    mislabelled.

    The rules:

    - A CHILD's identity is its LEAF, so the leaf must correspond.
    - A LITERAL parent must correspond too ('stalpha/default/data' is not
      'stbravo/default/data'). A parent carrying a placeholder is unresolvable
      and cannot be compared - which is exactly when the leaf carries the
      decision alone.
    - A leaf may itself be runtime-named ('parent/child-[hash]'), so it is
      compared the way a top-level name is: exact when literal, static prefix
      when not.
    """
    def _prefix_ok(declared: str, deployed: str) -> bool:
        static_prefix = declared.split("[")[0].strip()
        if "[" not in declared:
            return declared == deployed
        return (len(static_prefix) < 3
                or deployed.startswith(static_prefix)
                or static_prefix in deployed)

    if not bicep_name or not cand_name:
        return False

    if "/" in bicep_name:
        if "/" not in cand_name:
            return False
        b_parent, _, b_leaf = bicep_name.rpartition("/")
        d_parent, _, d_leaf = cand_name.rpartition("/")
        if "[" not in b_parent and b_parent != d_parent:
            return False
        return _prefix_ok(b_leaf, d_leaf)

    static_prefix = bicep_name.split("[")[0].strip()
    return (len(static_prefix) < 3
            or cand_name.startswith(static_prefix)
            or static_prefix in cand_name)


def _scope_to_target_rg(bicep_resource: dict, candidates: list[dict]) -> list[dict]:
    """Keep only candidates in the resource group the declaration deploys into.

    A subscription-scoped declaration records `_target_rg`, and can only be
    satisfied by a live resource IN that group. Name shape separates siblings
    like 'stl' (logging) and 'stg' (general) only while BOTH are alive: delete
    the logging resource group and the apps account becomes the ONLY unmatched
    candidate of its type, which the caller then treats as a "perfect match" at
    high confidence. That hid the real deletion and orphaned the survivor into a
    false missing_in_azure (live, 2026-08-03).

    Applied before the candidate count is judged, so the lone-candidate
    short-circuit is scoped too - filtering inside the tie-breaker alone left
    exactly this case unguarded.

    Candidates whose resource group is unknown are left alone: a collector that
    does not populate resource_group must not make every declaration read as
    missing.
    """
    target_rg = (bicep_resource.get("_target_rg") or "").lower()
    if not target_rg or not any(c.get("resource_group") for c in candidates):
        return candidates
    return [
        c for c in candidates
        if (c.get("resource_group") or "").lower() == target_rg
    ]


def smart_match_resources(
    bicep_resources: list[dict],
    azure_resources: list[dict],
    unresolvable: dict[str, list[str]]
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Attempt to match unresolvable Bicep resources to deployed Azure resources.

    Returns:
        (matched_resources, unmatched_bicep, unmatched_azure)
    """
    matched = []
    unmatched_bicep = bicep_resources.copy()
    unmatched_azure = azure_resources.copy()

    # Group resources by type for faster matching
    azure_by_type = defaultdict(list)
    for resource in azure_resources:
        resource_type = resource.get('type', '')
        azure_by_type[resource_type].append(resource)

    # Try to match unresolvable Bicep resources
    for bicep_resource in bicep_resources:
        resource_type = bicep_resource.get('type', '')
        resource_name = bicep_resource.get('name', '')

        # Only try to match if name is unresolvable
        if not _has_unresolvable_expression(resource_name):
            continue

        # Find unmatched Azure resources of the same type. Compare case-
        # insensitively: Resource Graph returns lowercase types
        # (microsoft.storage/storageaccounts) but Bicep is PascalCase.
        rtype_lower = resource_type.lower()
        candidates = [r for r in unmatched_azure if (r.get('type') or '').lower() == rtype_lower]
        candidates = _scope_to_target_rg(bicep_resource, candidates)

        # EVERY candidate count goes through _find_best_match, including one.
        #
        # A lone candidate used to be taken as a "perfect match" unconditionally,
        # skipping the child-leaf guard that _find_best_match applies. A DELETION
        # is what reduces the pool to one, so deleting a declared child routed the
        # match around the very guard that would have caught it - and raised the
        # confidence from medium to high on the way.
        #
        # Live 2026-08-11: `sqldrift[86c9cbf6]/driftdb` was deleted, leaving only
        # the undeclared system database `sqldrift<hash>/master`. The declared
        # child matched `master` at confidence 'high', so the deletion vanished
        # from the report AND an undeclared extra was absorbed - a false negative
        # that drift_count can never reveal.
        #
        # _find_best_match already accepts a sole candidate (`len(candidates) == 1`
        # short-circuits its prefix/suffix threshold), so nothing that legitimately
        # matched before stops matching; only leaf-incompatible pairs are refused.
        best_match = _find_best_match(bicep_resource, candidates)
        if best_match:
            sole = len(candidates) == 1
            matched_resource = {
                **bicep_resource,
                'matched_to': best_match.get('name'),
                'match_confidence': 'high' if sole else 'medium',
                'match_reason': (
                    'Same resource type, unresolvable name in Bicep' if sole
                    else 'Same resource type, possible match among multiple candidates'
                ),
                'actual_deployed_name': best_match.get('name'),
            }
            matched.append(matched_resource)

            # Remove from unmatched lists
            unmatched_bicep.remove(bicep_resource)
            unmatched_azure.remove(best_match)

    return matched, unmatched_bicep, unmatched_azure


#: The shared contract for both affix primitives below and for
#: `activity_log._shared_affix_len`: **case-insensitive, folded by the function
#: itself**, never by the caller.
#:
#: These were nested inside _find_best_match and case-SENSITIVE, working only
#: because both call sites happened to lowercase first. `_shared_affix_len`
#: folds internally. Two primitives computing the same thing under opposite
#: conventions is how a comparison silently under-counts the day someone passes
#: a raw Azure name - which arrives mixed-case, since ARM preserves the casing a
#: resource was created with.
#:
#: Deliberately NOT shared with activity_log by import. That module answers a
#: different question and stays independent of the pairing path - see
#: tests/test_identity_matching_boundary.py. What is shared is the CONTRACT,
#: pinned by a test asserting the two agree.


def _common_prefix_len(a: str, b: str) -> int:
    """Length of the longest common prefix, case-insensitively."""
    a, b = a.lower(), b.lower()
    n = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        n += 1
    return n


def _common_suffix_len(a: str, b: str) -> int:
    """Length of the longest common suffix, case-insensitively."""
    a, b = a.lower(), b.lower()
    n = 0
    for ca, cb in zip(reversed(a), reversed(b)):
        if ca != cb:
            break
        n += 1
    return n


def _find_best_match(bicep_resource: dict, candidates: list[dict]) -> dict:
    """
    Find the best matching Azure resource from candidates.

    Returns None when no candidate is a credible match. A WRONG match is far
    worse than none: it fabricates property drift against an unrelated resource
    AND orphans the real one (which then false-flags extra/missing). Seen live:
    a function app's 'format(...)/appsettings' matched 'app-test-drift/web'.

    Uses heuristics like creation time, naming conventions, etc.
    """
    if not candidates:
        return None

    # Prefer the candidate sharing the longest name prefix with the Bicep name.
    # The Bicep name is partially resolved (e.g. 'contosodevstgtake(uniqueString(
    # ...))'); its literal lead ('contosodevstg') still distinguishes a 'general'
    # storage from a 'logging' one ('contosodevstl') when several of the same type
    # exist. Longest-common-prefix is robust to the glued-on function tokens.
    bicep_name = (bicep_resource.get('name') or '').lower()

    # 'parent/child' names: the CHILD LEAF is the resource's identity, so it must
    # correspond exactly - an 'appsettings' config is never a 'web' config, no
    # matter how the (possibly unresolved) parent segment scores. Mirrors the
    # sibling guard in property_drift._match_by_fuzzy_tokens. Parent segments are
    # deliberately NOT compared: they are frequently unresolved expressions.
    candidates = _scope_to_target_rg(bicep_resource, candidates)
    if not candidates:
        return None

    if "/" in bicep_name:
        leaf = bicep_name.rsplit("/", 1)[1]
        candidates = [
            c for c in candidates
            if "/" in (c.get('name') or '')
            and (c.get('name') or '').lower().rsplit("/", 1)[1] == leaf
        ]
        if not candidates:
            return None

    # Prefix + suffix: a child name like 'sqldrift[86c9cbf6]/driftdb' shares
    # the same prefix with every sibling of the same server ('.../driftdb' and
    # '.../master'); the literal CHILD segment at the end disambiguates.
    best, best_prefix, best_suffix, best_score = None, 0, 0, -1
    for c in candidates:
        cname = (c.get('name') or '').lower()
        p = _common_prefix_len(bicep_name, cname)
        s = _common_suffix_len(bicep_name, cname)
        if p + s > best_score:
            best_score, best_prefix, best_suffix, best = p + s, p, s, c

    # Accept on the SAME signal the winner was selected with (prefix OR suffix).
    # Validating on the PREFIX alone discarded correct winners whose bicep name
    # leads with an unresolved expression - "format('func-drift-{0}', ...)"
    # shares only 'f' with 'func-drift-<hash>', so the real match was thrown away
    # and candidates[0] returned instead (live: matched 'app-test-drift/web').
    if len(candidates) == 1 or best_prefix >= 3 or best_suffix >= 3:
        return best if best is not None else candidates[0]

    # No signal at all (a fully unresolved name expression, e.g. two storage
    # accounts sharing "toLower(format('{0}st{1}', ...))"): pair in order. Each
    # match consumes its candidate, so N bicep <-> N live still pair up 1:1.
    return candidates[0]


def annotate_drifts_with_matches(
    drifts: list[dict],
    matched_resources: list[dict]
) -> list[dict]:
    """
    Annotate drift items with smart matching information.

    Updates drift records to show if they're actually matched resources
    with unresolvable names.
    """
    annotated = []

    # Create a map of matched deployments. Key on (lowercased type, name): the
    # matched resource carries the Bicep PascalCase type while the drift carries
    # the live lowercase type, so a case-sensitive key would never match.
    matched_map = {}
    for resource in matched_resources:
        key = ((resource.get('type') or '').lower(), resource.get('matched_to'))
        matched_map[key] = resource

    for drift in drifts:
        drift_copy = drift.copy()

        # Check if this drift is a matched resource
        key = ((drift.get('type') or '').lower(), drift.get('name'))
        if key in matched_map:
            matched = matched_map[key]
            drift_copy['is_matched'] = True
            drift_copy['match_confidence'] = matched.get('match_confidence')
            drift_copy['match_reason'] = matched.get('match_reason')
            drift_copy['bicep_name_expression'] = matched.get('name')
            drift_copy['drift_type'] = 'matched_unresolvable'

        annotated.append(drift_copy)

    return annotated
