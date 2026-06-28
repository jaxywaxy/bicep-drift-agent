"""
Parse and apply .drift-ignore patterns to filter drift results.
"""

import re
from pathlib import Path
from typing import List, Optional
import yaml


class IgnorePattern:
    """A single ignore pattern for drift filtering."""

    def __init__(self, pattern_dict: dict):
        self.resource_type: Optional[str] = pattern_dict.get("resource_type")
        self.resource_name: Optional[str] = pattern_dict.get("resource_name")
        self.drift_type: Optional[str] = pattern_dict.get("drift_type")
        self.reason: Optional[str] = pattern_dict.get("reason")

        # Compile regex patterns if they look like regex
        self.resource_type_regex = (
            self._compile_pattern(self.resource_type) if self.resource_type else None
        )
        self.resource_name_regex = (
            self._compile_pattern(self.resource_name) if self.resource_name else None
        )
        self.drift_type_regex = (
            self._compile_pattern(self.drift_type) if self.drift_type else None
        )

    @staticmethod
    def _compile_pattern(pattern: str) -> Optional[re.Pattern]:
        """Compile a string into a regex pattern."""
        if not pattern:
            return None

        try:
            # If it looks like a glob pattern, convert to regex
            if "*" in pattern or "?" in pattern:
                pattern = pattern.replace("*", ".*").replace("?", ".")
            return re.compile(f"^{pattern}$", re.IGNORECASE)
        except re.error:
            return None

    def matches(self, resource_type: str, resource_name: str, drift_type: str) -> bool:
        """Check if this pattern matches a drift."""
        if self.resource_type_regex and not self.resource_type_regex.match(
            resource_type
        ):
            return False

        if self.resource_name_regex and not self.resource_name_regex.match(
            resource_name
        ):
            return False

        if self.drift_type_regex and not self.drift_type_regex.match(drift_type):
            return False

        return True


class IgnorePatternList:
    """Load and apply a list of ignore patterns."""

    def __init__(self, patterns: List[dict] = None):
        self.patterns = [IgnorePattern(p) for p in (patterns or [])]

    @classmethod
    def from_file(cls, file_path: Path) -> "IgnorePatternList":
        """Load ignore patterns from a YAML file."""
        if not file_path.exists():
            return cls([])

        with open(file_path) as f:
            data = yaml.safe_load(f) or {}

        patterns = data.get("ignore", [])
        if not isinstance(patterns, list):
            patterns = []

        return cls(patterns)

    def filter_drifts(self, drifts: list) -> tuple[list, list]:
        """
        Filter drifts by ignore patterns.

        Returns:
            (filtered_drifts, ignored_drifts)
        """
        filtered = []
        ignored = []

        for drift in drifts:
            resource_type = drift.get("type", "")
            resource_name = drift.get("name", "")
            drift_type = drift.get("drift_type", "")

            is_ignored = False

            # For property-level drifts, also check against property names
            if drift_type == "property_drift":
                # Get property names that changed
                details = drift.get("details", {})
                changed_props = details.get("changed_properties", {})
                prop_names = list(changed_props.keys())

                # Check if any pattern matches resource + property combination
                for pattern in self.patterns:
                    # If pattern has drift_type, check if it matches property names
                    if pattern.drift_type:
                        for prop_name in prop_names:
                            if pattern.resource_type_regex.match(resource_type) if pattern.resource_type_regex else True:
                                if pattern.drift_type_regex.match(prop_name):
                                    drift["ignored_reason"] = pattern.reason or "Matched ignore pattern"
                                    ignored.append(drift)
                                    is_ignored = True
                                    break
                    if is_ignored:
                        break

            # Standard pattern matching for non-property drifts or if not already ignored
            if not is_ignored:
                for pattern in self.patterns:
                    if pattern.matches(resource_type, resource_name, drift_type):
                        drift["ignored_reason"] = pattern.reason or "Matched ignore pattern"
                        ignored.append(drift)
                        is_ignored = True
                        break

            if not is_ignored:
                filtered.append(drift)

        return filtered, ignored

    def print_summary(self):
        """Print a summary of loaded patterns."""
        if not self.patterns:
            print("No ignore patterns loaded")
            return

        print(f"Loaded {len(self.patterns)} ignore pattern(s):")
        for i, pattern in enumerate(self.patterns, 1):
            parts = []
            if pattern.resource_type:
                parts.append(f"type={pattern.resource_type}")
            if pattern.resource_name:
                parts.append(f"name={pattern.resource_name}")
            if pattern.drift_type:
                parts.append(f"drift={pattern.drift_type}")
            print(f"  {i}. {', '.join(parts)}")
            if pattern.reason:
                print(f"     Reason: {pattern.reason}")
