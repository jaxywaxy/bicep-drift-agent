"""
Parse and apply .drift-ignore patterns to filter drift results.
"""

import re
import logging
import fnmatch
from pathlib import Path
from typing import List, Optional
import yaml

logger = logging.getLogger(__name__)


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
    def _compile_pattern(pattern: str) -> Optional[str]:
        """Store pattern for fnmatch-based matching (avoids ReDoS vulnerability).

        Uses fnmatch instead of regex to avoid catastrophic backtracking issues.
        fnmatch is safe for glob patterns and provides the same wildcard semantics.

        Args:
            pattern: Glob pattern (e.g., "*.txt", "vm-*-prod")

        Returns:
            Normalized pattern for fnmatch or None if invalid
        """
        if not pattern:
            return None

        # fnmatch handles glob patterns safely without ReDoS risk
        return pattern.lower()

    def matches(self, resource_type: str, resource_name: str, drift_type: str) -> bool:
        """Check if this pattern matches a drift using fnmatch."""
        if self.resource_type_regex:
            if not fnmatch.fnmatch(resource_type.lower(), self.resource_type_regex):
                return False

        if self.resource_name_regex:
            if not fnmatch.fnmatch(resource_name.lower(), self.resource_name_regex):
                return False

        if self.drift_type_regex:
            if not fnmatch.fnmatch(drift_type.lower(), self.drift_type_regex):
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
                            resource_matches = (
                                fnmatch.fnmatch(resource_type.lower(), pattern.resource_type_regex)
                                if pattern.resource_type_regex else True
                            )
                            if resource_matches:
                                if fnmatch.fnmatch(prop_name.lower(), pattern.drift_type_regex):
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

    def log_summary(self):
        """Log a summary of loaded patterns."""
        if not self.patterns:
            logger.debug("No ignore patterns loaded")
            return

        logger.info(f"Loaded {len(self.patterns)} ignore pattern(s):")
        for i, pattern in enumerate(self.patterns, 1):
            parts = []
            if pattern.resource_type:
                parts.append(f"type={pattern.resource_type}")
            if pattern.resource_name:
                parts.append(f"name={pattern.resource_name}")
            if pattern.drift_type:
                parts.append(f"drift={pattern.drift_type}")
            logger.info(f"  {i}. {', '.join(parts)}")
            if pattern.reason:
                logger.debug(f"     Reason: {pattern.reason}")

    def print_summary(self):
        """Deprecated: Use log_summary() instead. Print a summary of loaded patterns."""
        self.log_summary()
