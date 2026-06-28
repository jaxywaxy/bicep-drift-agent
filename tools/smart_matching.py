"""
Smart resource matching for unresolvable expressions.

Detects runtime-generated names in Bicep templates and attempts to match
them to deployed resources by type.
"""

from typing import List, Dict, Tuple
from collections import defaultdict


UNRESOLVABLE_FUNCTIONS = {
    'uniqueString',
    'copyIndex',
    'guid',
    'utcNow',
    'deployment',
    'reference',
    'listKeys',
}


def detect_unresolvable_expressions(arm_template: Dict) -> Dict[str, List[str]]:
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
    """Check if a string contains unresolvable ARM functions."""
    if not isinstance(name_str, str):
        return False

    # Check for ARM function syntax
    if not ('[' in name_str and ']' in name_str):
        return False

    # Check for known unresolvable functions
    for func in UNRESOLVABLE_FUNCTIONS:
        if func in name_str:
            return True

    return False


def smart_match_resources(
    bicep_resources: List[Dict],
    azure_resources: List[Dict],
    unresolvable: Dict[str, List[str]]
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
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

        # Find unmatched Azure resources of the same type
        candidates = [r for r in unmatched_azure if r.get('type') == resource_type]

        if len(candidates) == 1:
            # Perfect match: one unresolvable Bicep resource and one unmatched Azure resource of same type
            matched_resource = {
                **bicep_resource,
                'matched_to': candidates[0].get('name'),
                'match_confidence': 'high',
                'match_reason': 'Same resource type, unresolvable name in Bicep',
                'actual_deployed_name': candidates[0].get('name'),
            }
            matched.append(matched_resource)

            # Remove from unmatched lists
            unmatched_bicep.remove(bicep_resource)
            unmatched_azure.remove(candidates[0])

        elif len(candidates) > 1:
            # Multiple candidates - try to pick the best match
            # Prefer resources with similar characteristics
            best_match = _find_best_match(bicep_resource, candidates)
            if best_match:
                matched_resource = {
                    **bicep_resource,
                    'matched_to': best_match.get('name'),
                    'match_confidence': 'medium',
                    'match_reason': 'Same resource type, possible match among multiple candidates',
                    'actual_deployed_name': best_match.get('name'),
                }
                matched.append(matched_resource)

                # Remove from unmatched lists
                unmatched_bicep.remove(bicep_resource)
                unmatched_azure.remove(best_match)

    return matched, unmatched_bicep, unmatched_azure


def _find_best_match(bicep_resource: Dict, candidates: List[Dict]) -> Dict:
    """
    Find the best matching Azure resource from candidates.

    Uses heuristics like creation time, naming conventions, etc.
    """
    if not candidates:
        return None

    # Simple heuristic: prefer most recently created (if metadata available)
    # For now, just return the first candidate
    # In a real implementation, could use more sophisticated matching
    return candidates[0]


def annotate_drifts_with_matches(
    drifts: List[Dict],
    matched_resources: List[Dict]
) -> List[Dict]:
    """
    Annotate drift items with smart matching information.

    Updates drift records to show if they're actually matched resources
    with unresolvable names.
    """
    annotated = []

    # Create a map of matched deployments
    matched_map = {}
    for resource in matched_resources:
        key = (resource.get('type'), resource.get('matched_to'))
        matched_map[key] = resource

    for drift in drifts:
        drift_copy = drift.copy()

        # Check if this drift is a matched resource
        key = (drift.get('type'), drift.get('name'))
        if key in matched_map:
            matched = matched_map[key]
            drift_copy['is_matched'] = True
            drift_copy['match_confidence'] = matched.get('match_confidence')
            drift_copy['match_reason'] = matched.get('match_reason')
            drift_copy['bicep_name_expression'] = matched.get('name')
            drift_copy['drift_type'] = 'matched_unresolvable'

        annotated.append(drift_copy)

    return annotated


def generate_match_report(matched: List[Dict]) -> str:
    """Generate a human-readable report of matched resources."""
    if not matched:
        return ""

    report = "## 🔗 Smart-Matched Resources\n\n"
    report += "These resources are defined in Bicep but have runtime-generated names:\n\n"

    for resource in matched:
        bicep_name = resource.get('name', 'unknown')
        azure_name = resource.get('matched_to', 'unknown')
        confidence = resource.get('match_confidence', 'unknown')
        reason = resource.get('match_reason', '')

        report += f"- **{resource.get('type')}**\n"
        report += f"  - Bicep name: `{bicep_name}`\n"
        report += f"  - Deployed as: `{azure_name}`\n"
        report += f"  - Confidence: {confidence}\n"
        if reason:
            report += f"  - Reason: {reason}\n"
        report += "\n"

    return report
