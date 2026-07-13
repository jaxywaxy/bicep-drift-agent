"""
Parse and apply .drift-ignore patterns to filter drift results.
"""

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
        self.property: Optional[str] = pattern_dict.get("property")
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
        self.property_regex = (
            self._compile_pattern(self.property) if self.property else None
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

    @staticmethod
    def _read(file_path: Path) -> list:
        """Read the raw 'ignore' pattern dicts from a YAML file (empty if missing)."""
        if not file_path or not Path(file_path).exists():
            return []
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
        patterns = data.get("ignore", [])
        return patterns if isinstance(patterns, list) else []

    @classmethod
    def from_file(cls, file_path: Path) -> "IgnorePatternList":
        """Load ignore patterns from a single YAML file."""
        return cls(cls._read(file_path))

    @classmethod
    def from_files(cls, *file_paths) -> "IgnorePatternList":
        """
        Load and MERGE ignore patterns from several YAML files (in order).

        Used for layered profiles: a universal baseline (the agent's own
        .drift-ignore) plus a per-landing-zone profile (the bicep repo's
        .drift-ignore). Later files are appended; all patterns apply.
        Missing files are skipped.
        """
        merged = []
        for p in file_paths:
            if p:
                merged.extend(cls._read(Path(p)))
        return cls(merged)

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

            # For property-level drifts, property-scoped patterns STRIP the
            # matching properties from the drift rather than ignoring the whole
            # record: a drift often carries an ignorable noisy property (AKS
            # agentPoolProfiles) alongside a real finding (authorizedIPRanges
            # added out-of-band) in the SAME record - dropping the record on any
            # single match would swallow the real finding with the noise. The
            # drift is only fully ignored when NO properties survive.
            if drift_type == "property_drift":
                details = drift.get("details", {})
                changed_props = details.get("changed_properties", {}) or {}
                last_reason = None

                for pattern in self.patterns:
                    if not pattern.property_regex:
                        continue
                    if pattern.resource_type_regex and not fnmatch.fnmatch(
                            resource_type.lower(), pattern.resource_type_regex):
                        continue
                    if pattern.resource_name_regex and not fnmatch.fnmatch(
                            resource_name.lower(), pattern.resource_name_regex):
                        continue
                    for prop_name in list(changed_props.keys()):
                        prop_lower = prop_name.lower()
                        # Match the property itself OR any nested sub-property, so a
                        # pattern like "properties.networkAcls" also covers
                        # "properties.networkAcls.defaultAction" / ".bypass".
                        if (fnmatch.fnmatch(prop_lower, pattern.property_regex)
                                or prop_lower.startswith(pattern.property_regex + ".")):
                            drift.setdefault("ignored_properties", {})[prop_name] = (
                                changed_props.pop(prop_name)
                            )
                            last_reason = pattern.reason or "Matched ignore pattern"

                if last_reason is not None and not changed_props:
                    drift["ignored_reason"] = last_reason
                    ignored.append(drift)
                    is_ignored = True

            # Standard pattern matching for non-property drifts or if not already ignored
            if not is_ignored:
                for pattern in self.patterns:
                    # Property-scoped patterns only apply to property_drift (handled above).
                    # Without this guard, a pattern like {type: KeyVault, property: networkAcls}
                    # would match ANY KeyVault drift - including missing_in_azure / extra_in_azure -
                    # because matches() does not consider the property field. That would wrongly
                    # suppress a manually-added (extra) or deleted (missing) resource.
                    if pattern.property_regex:
                        continue
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
            if pattern.property:
                parts.append(f"property={pattern.property}")
            logger.info(f"  {i}. {', '.join(parts)}")
            if pattern.reason:
                logger.debug(f"     Reason: {pattern.reason}")
