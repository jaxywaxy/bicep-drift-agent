"""
Characterization tests for the HTML report renderer.

html_report.py had ZERO test coverage while carrying the largest function in
the codebase (generate_html_report, 746 lines - ~4x the next). These tests were
written BEFORE extracting the 562-line static CSS block to a module constant,
to pin the rendered output; the extraction was then proven byte-identical
against a real 35-drift report.

They are deliberately behavioural, not golden-file: they assert the report
CONTAINS what each section is responsible for, so the renderer can be
refactored further without churning a snapshot, while a section silently
disappearing still fails.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.count_drifts import tally_report
from tools.html_report import _REPORT_CSS, generate_html_report


def _report(**overrides):
    """A compact report exercising every render path."""
    data = {
        "resource_group": "rg-drift-test",
        "bicep_file": "bicep/main.bicep",
        "drift_count": 3,
        "drifts": [
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "name": "nsg-drift-test",
                "drift_type": "property_drift",
                "details": {"changed_properties": {
                    "properties.securityRules": {
                        "desired": [{"name": "deny-ssh"}],
                        "actual": [{"name": "allow-rdp-anywhere"}],
                        "severity": "critical"}}},
                "owner": "platform",
                "change_origin": {"origin": "manual_change", "category": "out_of_band",
                                  "severity": "high", "expected": False,
                                  "changed_by": "someone@example.com",
                                  "reason": "Manual change"},
                "lifecycle": {"resource_id": "/subscriptions/s/rg/x/nsg-drift-test",
                              "events": [], "deleted_at": None,
                              "last_modified_at": "2026-07-15T01:00:00+00:00",
                              "last_modified_by": "someone@example.com"},
                "recommendation": "Remove the allow-rdp-anywhere rule.",
            },
            {
                "type": "Microsoft.Authorization/locks",
                "name": "keyvault-cannotdelete",
                "drift_type": "missing_in_azure",
                "details": {},
                "owner": "workload",
            },
            {
                "type": "microsoft.storage/storageaccounts",
                "name": "stunmanaged",
                "drift_type": "extra_in_azure",
                "details": {},
                "owner": "unknown",
            },
            {
                "type": "microsoft.keyvault/vaults",
                "name": "kvdrift3s7c",
                "drift_type": "matched_unresolvable",
                "details": {},
                "is_matched": True,
                "match_confidence": "high",
                "bicep_name_expression": "kvdrift[86c9cbf6]",
            },
        ],
        "property_drifts": [],
        "ignored_drifts": [{"type": "Microsoft.OperationalInsights/workspaces/tables",
                            "name": "log-x/CustomLog_CL", "drift_type": "missing_in_azure",
                            "details": {}, "ignored_reason": "Blanket ignore"}],
        "policy_enforced_drifts": [{
            "type": "microsoft.storage/storageaccounts", "name": "stpolicy",
            "drift_type": "property_drift",
            "details": {"changed_properties": {"properties.x": {"desired": 1, "actual": 2,
                                                                "severity": "info"}}},
            "change_origin": {"origin": "policy_dine", "category": "expected",
                              "severity": "info", "expected": True,
                              "policy_name": "Deploy diagnostics",
                              "reason": "Policy DINE"},
        }],
        "smart_matched": [{"type": "microsoft.keyvault/vaults",
                           "name": "kvdrift[86c9cbf6]", "matched_to": "kvdrift3s7c",
                           "match_confidence": "high", "match_reason": "same type"}],
        "agent_analysis": "## Summary\n\nThree drifts found.",
        "agent_usage": {"calls": 3, "input_tokens": 2751, "output_tokens": 3579,
                        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                        "models": ["claude-opus-4-8"], "estimated_cost_usd": 0.114655},
    }
    data.update(overrides)
    return data


def _render(**overrides):
    with tempfile.TemporaryDirectory() as d:
        src, out = Path(d) / "r-drift.json", Path(d) / "r-drift.html"
        src.write_text(json.dumps(_report(**overrides)))
        generate_html_report(src, out, "rg-drift-test", "bicep/main.bicep")
        return out.read_text()


class HtmlReportRenderTests(unittest.TestCase):
    def test_renders_valid_shell(self):
        h = _render()
        self.assertIn("<!DOCTYPE html>", h)
        self.assertIn("</html>", h)
        self.assertIn("<style>", h)
        self.assertIn("</style>", h)

    def test_drift_names_and_types_present(self):
        h = _render()
        for expected in ("nsg-drift-test", "keyvault-cannotdelete", "stunmanaged"):
            self.assertIn(expected, h)

    def test_critical_property_drift_rendered(self):
        h = _render()
        self.assertIn("properties.securityRules", h)
        self.assertIn("critical", h.lower())

    def test_agent_analysis_rendered(self):
        # The consolidated remediation narrative is now the report's remediation
        # content. (298ed60 had removed it as duplicating the per-drift
        # recommendation cards; those cards are gone - the narrative is ONE call
        # that sees every drift, so it can order the work and say "investigate
        # before overwriting", which N blind per-resource calls could not.)
        h = _render()
        self.assertIn("Remediation Analysis", h)
        self.assertIn("Three drifts found.", h)

    def test_per_drift_recommendation_cards_are_gone(self):
        # The old O(N)-call cards. Pinned so the fan-out is not reintroduced.
        self.assertNotIn('class="recommendation-item"', _render())

    def test_analysis_markdown_is_rendered_not_raw(self):
        h = _render(agent_analysis="## Plan\n\n| Order | Action |\n|---|---|\n| 1 | Redeploy |")
        self.assertIn("<table>", h)
        self.assertIn("<h2>Plan</h2>", h)
        self.assertNotIn("|---|---|", h)

    def test_analysis_cannot_inject_markup(self):
        # The narrative is model output quoting live resource names. We escape
        # only '<' (a tag cannot open without it) before markdown, which itself
        # escapes the remaining '>' in prose - so blockquotes still work.
        h = _render(agent_analysis="## Plan\n\n<script>alert(1)</script> and <img src=x onerror=y>")
        self.assertNotIn("<script>", h)
        self.assertNotIn("<img src=x", h)
        self.assertIn("&lt;script&gt;", h)

    def test_analysis_code_block_quotes_not_double_escaped(self):
        # Regression: html.escape() before markdown turned '"' into &quot;,
        # then markdown escaped the '&' inside code -> literal &quot; shown in
        # az CLI commands in the report.
        cmd = 'az ad sp show --id c7ee07ee --query "{name:displayName, appId:appId}"'
        h = _render(agent_analysis=f"## Plan\n\n```bash\n{cmd}\n```\n")
        # Single-escaped &quot; in <code> is correct (renders as "); the bug
        # was the double-escaped &amp;quot; rendering literally as &quot;.
        self.assertNotIn("&amp;quot;", h)
        self.assertIn("--query &quot;{name:displayName, appId:appId}&quot;", h)

    def test_analysis_inline_code_angle_brackets_survive(self):
        # '<assignment_id>' inside inline code must render as markdown-escaped
        # code, not double-escaped and not live markup.
        h = _render(agent_analysis="Run `az role assignment delete --ids <assignment_id>` first.")
        self.assertIn("&lt;assignment_id&gt;", h)
        self.assertNotIn("&amp;lt;", h)

    def test_analysis_blockquote_renders(self):
        # '>' was previously escaped, so "> Note:" showed as literal &gt; text.
        h = _render(agent_analysis="## Plan\n\n> Note: verify before deleting.\n")
        self.assertIn("<blockquote>", h)
        self.assertNotIn("&gt; Note:", h)

    def test_no_analysis_section_when_absent(self):
        self.assertNotIn("Remediation Analysis", _render(agent_analysis=None))

    def test_agent_usage_footer_shows_cost(self):
        h = _render()
        self.assertIn("claude-opus-4-8", h)
        self.assertIn("0.11", h)

    def test_usage_footer_absent_when_no_usage(self):
        h = _render(agent_usage=None)
        self.assertNotIn("claude-opus-4-8", h)

    def test_policy_enforced_section_rendered(self):
        self.assertIn("Deploy diagnostics", _render())

    def test_smart_matched_section_rendered(self):
        h = _render()
        self.assertIn("kvdrift[86c9cbf6]", h)

    def test_owner_badges_rendered(self):
        h = _render()
        self.assertIn("platform", h)
        self.assertIn("workload", h)

    def test_clean_report_renders(self):
        h = _render(drifts=[], drift_count=0, property_drifts=[],
                    policy_enforced_drifts=[], smart_matched=[], agent_analysis=None)
        self.assertIn("<!DOCTYPE html>", h)
        self.assertIn("rg-drift-test", h)

    def test_html_escaping_of_hostile_names(self):
        # A resource name must never break out into markup.
        h = _render(drifts=[{"type": "microsoft.storage/storageaccounts",
                             "name": "<script>alert(1)</script>",
                             "drift_type": "extra_in_azure", "details": {}}])
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("&lt;script&gt;", h)


class ReportHeadlineMetricTests(unittest.TestCase):
    """The report's headline must say the same thing as the CI summary.

    The CI summary was reworked to lead with CHANGED RESOURCES + criticals, with
    property paths demoted to detail. The report still led with "Total Issues"
    and had no critical count at all, so the two surfaces described the same run
    differently. Both now count via count_drifts.tally_report.
    """

    def test_metrics_match_the_ci_summary_counts(self):
        h = _render()
        counts = tally_report(_report())
        # 1 property_drift + 1 missing + 1 extra; matched_unresolvable excluded.
        self.assertEqual(counts["drift_count"], 1)
        self.assertEqual(counts["critical_count"], 1)
        for label, number in (
            ("Changed Resources", counts["drift_count"]),
            ("Critical", counts["critical_count"]),
            ("Missing", counts["missing_count"]),
            ("Extra", counts["extra_count"]),
            ("Total Issues", counts["total_issues"]),
        ):
            card = re.search(
                rf'metric-label">{label}</div>\s*<div class="metric-number">(\d+)<',
                h,
            )
            self.assertIsNotNone(card, f"no metric card for {label}")
            self.assertEqual(int(card.group(1)), number, f"{label} card disagrees with CI")

    def test_property_paths_are_detail_not_a_headline(self):
        # Path counts track comparator granularity, so they appear as a sub-line
        # under Changed Resources - never as a metric card of their own.
        h = _render()
        self.assertIn("property path(s)", h)
        self.assertNotIn('metric-label">Property', h)

    def test_critical_card_reflects_severity_not_record_count(self):
        # Two cosmetic edits and two stripped security settings both print as
        # "2" resources; only the critical card separates them.
        clean = _report()
        for drift in clean["drifts"]:
            for change in (drift.get("details") or {}).get("changed_properties", {}).values():
                change["severity"] = "info"
        h = _render(drifts=clean["drifts"])
        card = re.search(r'metric-label">Critical</div>\s*<div class="metric-number">(\d+)<', h)
        self.assertEqual(card.group(1), "0")


class ReportEncodingTests(unittest.TestCase):
    """The report is written with an explicit utf-8 encoding, never the locale
    default. Its status badges and section headings are emoji, so on a runner
    with LANG unset (C/POSIX -> ascii) the default would raise
    UnicodeEncodeError and the report would never be written at all."""

    def test_report_is_written_as_utf_8_under_a_c_locale(self):
        """Runs the real generator in a subprocess under LC_ALL=C.

        Deliberately NOT a mock: open() resolves its default encoding in C, at
        call time, from the process locale - patching locale.getencoding or
        locale.getpreferredencoding does not change it, so a mocked version of
        this test passes whether or not the fix is present (verified). Only a
        genuinely ascii-default interpreter reproduces the runner.
        """
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as d:
            src, out = Path(d) / "r-drift.json", Path(d) / "r-drift.html"
            src.write_text(json.dumps(_report()), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-c",
                 "import sys, pathlib;"
                 "sys.path.insert(0, sys.argv[3]);"
                 "from tools.html_report import generate_html_report;"
                 "generate_html_report(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]),"
                 " 'rg-drift-test', 'bicep/main.bicep')",
                 str(src), str(out), str(repo)],
                env={**os.environ, "LC_ALL": "C", "LANG": "C",
                     "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"},
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0,
                             f"report generation died under a C locale:\n{proc.stderr}")
            raw = out.read_bytes()
        self.assertIn("⚠️".encode(), raw)
        self.assertIn('<meta charset="UTF-8">', raw.decode("utf-8"))

    def test_non_ascii_resource_names_survive_the_round_trip(self):
        # Azure values (tags, descriptions, display names) carry any Unicode.
        h = _render(drifts=[{"type": "microsoft.storage/storageaccounts",
                             "name": "st-café-数据", "drift_type": "extra_in_azure",
                             "details": {}}])
        self.assertIn("st-café-数据", h)


class ReportCssTests(unittest.TestCase):
    """The CSS was extracted from an f-string, where all 168 of its braces had
    to be doubled. Pin that it is now literal, static CSS."""

    def test_css_is_a_plain_static_string(self):
        self.assertIsInstance(_REPORT_CSS, str)
        self.assertGreater(len(_REPORT_CSS), 1000)

    def test_css_braces_are_literal_not_doubled(self):
        self.assertNotIn("{{", _REPORT_CSS)
        self.assertNotIn("}}", _REPORT_CSS)
        self.assertIn("box-sizing: border-box;", _REPORT_CSS)

    def test_css_has_no_interpolation_placeholders(self):
        # Static CSS: no leftover {name} that an f-string would have filled.
        self.assertEqual(re.findall(r"(?<!\{)\{[a-z_]+\}(?!\})", _REPORT_CSS), [])

    def test_css_is_embedded_verbatim_in_output(self):
        self.assertIn(_REPORT_CSS, _render())


def _inherit_tag_group(n, policy="drift-inherit-environment", actual="production",
                       days=None):
    """n resources carrying the SAME policy-imposed tag - the real-world shape.

    An inherit-tag assignment applies to every resource in the RG, so this is
    what the section actually receives; a one-record fixture cannot exercise it.
    """
    return [{
        "type": "Microsoft.Network/dnsZones",
        "name": f"zone-{i}.example.com",
        "drift_type": "property_drift",
        "details": {"policy_enforced_summary": f"tags.environment: test -> {actual}"},
        "change_origin": {"origin": "policy_modify", "expected": True,
                          "policy_name": policy,
                          "timestamp": f"2026-07-{(days[i] if days else 27):02d}T00:00:00Z"},
        "policy_enforced_properties": {"tags.environment": {
            "desired": "test", "actual": actual, "policy_assignment": policy}},
    } for i in range(n)]


def _governance_html(policy_enforced, **kw):
    data = _report(agent_analysis="## TL;DR\nnarrative",
                   policy_enforced_drifts=policy_enforced, **kw)
    with tempfile.TemporaryDirectory() as d:
        src, out = Path(d) / "in.json", Path(d) / "out.html"
        src.write_text(json.dumps(data))
        generate_html_report(src, out, "rg-drift-test", "bicep/main.bicep")
        return out.read_text()


class GovernanceGroupingTests(unittest.TestCase):
    """One governance fact should occupy one row, not one row per resource.

    An inherit-tag policy fans out across the whole RG: a live report carried
    nineteen rows differing only in the resource name, a screen and a half of
    scrolling for a single fact. Grouping is the normal case for Modify/DINE
    effects, so the section groups by (what changed, who imposed it).
    """

    def _rows(self, html):
        body = html[html.index("Policy / System-Enforced Changes"):]
        return body[:body.index("</table>")].count("<tr>") - 1  # minus the header row

    def test_resources_sharing_one_policy_change_collapse_to_one_row(self):
        html = _governance_html(_inherit_tag_group(19))
        self.assertEqual(self._rows(html), 1)
        self.assertIn("<strong>19 resources</strong>", html)

    def test_the_collapsed_row_still_names_every_resource(self):
        # Grouping must not lose evidence - the names move behind a <details>,
        # they do not leave the report.
        html = _governance_html(_inherit_tag_group(19))
        for i in range(19):
            self.assertIn(f"zone-{i}.example.com", html)

    def test_different_facts_do_not_merge(self):
        # Same policy, different imposed value: two distinct facts, two rows.
        # Collapsing these would state something untrue about the estate.
        html = _governance_html(_inherit_tag_group(3)
                                + _inherit_tag_group(2, actual="staging"))
        self.assertEqual(self._rows(html), 2)
        self.assertIn("production", html)
        self.assertIn("staging", html)

    def test_different_policies_do_not_merge(self):
        html = _governance_html(_inherit_tag_group(3)
                                + _inherit_tag_group(3, policy="other-assignment"))
        self.assertEqual(self._rows(html), 2)

    def test_a_single_resource_is_not_hidden_behind_a_disclosure(self):
        # One resource is not a list; making the reader click to see one name
        # is worse than the duplication grouping set out to fix.
        html = _governance_html(_inherit_tag_group(1))
        self.assertIn("zone-0.example.com", html)
        self.assertNotIn("1 resources", html)

    def test_a_group_spanning_days_reports_the_range(self):
        html = _governance_html(_inherit_tag_group(3, days={0: 24, 1: 26, 2: 25}))
        self.assertIn("2026-07-24 &ndash; 2026-07-26", html)

    def test_a_group_with_no_timestamps_renders(self):
        # An in-flight Modify leaves no activity-log event, which is precisely
        # why this section exists - the common case must not crash the report.
        rows = _inherit_tag_group(3)
        for r in rows:
            r["change_origin"]["timestamp"] = ""
        html = _governance_html(rows)
        self.assertEqual(self._rows(html), 1)

    def test_grouping_is_deterministic(self):
        rows = _inherit_tag_group(3) + _inherit_tag_group(2, actual="staging")
        self.assertEqual(_governance_html(rows), _governance_html(rows))


class DriftDetailsCellTests(unittest.TestCase):
    """The Details cell renders the change; it does not dump the record.

    It used to be json.dumps(indent=2) in a <pre> inside a fixed-layout
    six-column table - developer syntax restating what the Modified
    Configuration section above had already shown properly.
    """

    def test_a_changed_property_renders_as_values_not_json(self):
        h = _render()
        cell = h[h.index("Drift Details"):]
        self.assertIn("detail-change", cell)
        self.assertNotIn("&quot;changed_properties&quot;", cell)
        self.assertNotIn("&quot;desired&quot;", cell)

    def test_the_property_path_and_both_values_survive(self):
        h = _render(drifts=[{
            "type": "Microsoft.Storage/storageAccounts", "name": "stdrift",
            "drift_type": "property_drift", "owner": "workload",
            "details": {"changed_properties": {"properties.allowBlobPublicAccess": {
                "desired": False, "actual": True, "severity": "critical"}}},
        }])
        self.assertIn("properties.allowBlobPublicAccess", h)
        self.assertIn("false", h)
        self.assertIn("true", h)
        self.assertIn('<span class="badge critical">critical</span>', h)

    def test_details_keys_we_do_not_model_are_still_shown(self):
        # This is the diagnostic cell. Dropping an unanticipated key would lose
        # evidence silently, which is worse than an ugly cell.
        h = _render(drifts=[{
            "type": "T", "name": "n", "drift_type": "property_drift",
            "details": {"changed_properties": {}, "policy_enforced_summary": "tag imposed",
                        "some_future_key": "keep me"},
        }])
        self.assertIn("policy_enforced_summary", h)
        self.assertIn("keep me", h)

    def test_a_hostile_property_path_is_escaped(self):
        h = _render(drifts=[{
            "type": "T", "name": "n", "drift_type": "property_drift",
            "details": {"changed_properties": {"<img src=x onerror=alert(1)>": {
                "desired": "a", "actual": "<script>", "severity": "low"}}},
        }])
        self.assertNotIn("<img src=x", h)
        self.assertNotIn("<script>", h)

    def test_a_drift_with_no_details_says_so(self):
        h = _render(drifts=[{"type": "T", "name": "n", "drift_type": "extra_in_azure"}])
        self.assertIn("No additional details", h)


class OwnerBadgeTests(unittest.TestCase):
    """Ownership is routing information, not a judgement.

    The badges reused .modified (orange) and .origin-policy (green), so an
    owner sat beside a drift-type badge in the same row wearing the same
    colours and read as a second severity signal.
    """

    def test_owner_badges_do_not_reuse_the_severity_or_origin_palette(self):
        h = _render(drifts=[
            {"type": "T", "name": "a", "drift_type": "property_drift", "owner": "workload"},
            {"type": "T", "name": "b", "drift_type": "property_drift", "owner": "platform"},
        ])
        self.assertIn("badge owner-workload", h)
        self.assertIn("badge owner-platform", h)
        self.assertNotIn('badge modified" title="Owned by', h)
        self.assertNotIn('badge origin-policy" title="Owned by', h)

    def test_both_owner_classes_are_styled(self):
        for cls in ("owner-workload", "owner-platform"):
            self.assertIn(f".badge.{cls}", _REPORT_CSS)


class PolicyEnforcedSectionTests(unittest.TestCase):
    """Placement and content of the governance section.

    A live reader (2026-07-27) read the report and concluded the policy-imposed
    tag change "isn't reported or fixed". It was reported - but the section sat
    AFTER the remediation narrative, and its rows named only the resource, never
    the property or the two values. Both are fixed here; both are asserted,
    because either one alone reproduces the same wrong conclusion.
    """

    def _html(self, **kw):
        data = _report(
            agent_analysis="## TL;DR\nnarrative",
            policy_enforced_drifts=[{
                "type": "Microsoft.Network/dnsZones",
                "name": "drifttest.example.com",
                "drift_type": "property_drift",
                "details": {"changed_properties": {}},
                "change_origin": {"origin": "policy_modify", "expected": True,
                                  "policy_name": "drift-inherit-environment",
                                  "timestamp": "2026-07-27T00:00:00Z"},
                "policy_enforced_properties": {"tags.environment": {
                    "desired": "test", "actual": "production",
                    "policy_assignment": "drift-inherit-environment"}},
            }],
            **kw)
        with tempfile.TemporaryDirectory() as d:
            src, out = Path(d) / "in.json", Path(d) / "out.html"
            src.write_text(json.dumps(data))
            generate_html_report(src, out, "rg-drift-test", "bicep/main.bicep")
            return out.read_text()

    def test_governance_precedes_the_remediation_narrative(self):
        html = self._html()
        policy_at = html.index("Policy / System-Enforced Changes")
        analysis_at = html.index("Remediation Analysis")
        drift_at = html.index("Drift Details")

        self.assertLess(drift_at, policy_at, "governance must follow the drift detail")
        self.assertLess(policy_at, analysis_at,
                        "governance must come BEFORE the remediation narrative")

    def test_the_row_names_the_property_and_both_values(self):
        html = self._html()
        section = html[html.index("Policy / System-Enforced Changes"):]
        section = section[:section.index("</table>")]

        self.assertIn("tags.environment", section)
        self.assertIn("test", section)
        self.assertIn("production", section)

    def test_the_row_names_the_assignment(self):
        section = self._html()
        self.assertIn("drift-inherit-environment", section)

    def test_a_dine_created_resource_renders_without_claimed_properties(self):
        """A DINE-created resource is policy-enforced as a WHOLE resource - it has
        no policy_enforced_properties. The Change cell must degrade, not vanish or
        raise."""
        data = _report(policy_enforced_drifts=[{
            "type": "Microsoft.Insights/diagnosticSettings", "name": "kv-audit",
            "drift_type": "extra_in_azure", "details": {},
            "change_origin": {"origin": "policy_dine", "expected": True,
                              "policy_name": "deploy-kv-diagnostics",
                              "timestamp": "2026-07-27T00:00:00Z"},
        }])
        with tempfile.TemporaryDirectory() as d:
            src, out = Path(d) / "in.json", Path(d) / "out.html"
            src.write_text(json.dumps(data))
            generate_html_report(src, out, "rg-drift-test", "bicep/main.bicep")
            html = out.read_text()

        self.assertIn("kv-audit", html)
        self.assertIn("whole resource", html)

    def test_section_is_absent_when_nothing_is_policy_enforced(self):
        data = _report(policy_enforced_drifts=[])
        with tempfile.TemporaryDirectory() as d:
            src, out = Path(d) / "in.json", Path(d) / "out.html"
            src.write_text(json.dumps(data))
            generate_html_report(src, out, "rg-drift-test", "bicep/main.bicep")
            self.assertNotIn("Policy / System-Enforced Changes", out.read_text())

    def test_the_header_counts_the_governance_rows_it_is_about_to_show(self):
        # The complaint that started this: a header reading "Total Issues: 1"
        # over a table of governance rows reads as a report contradicting
        # itself. Every row the section renders must be accounted for above.
        # Uses the MULTI-resource fixture on purpose. With a single record the
        # card, the heading and the row count are all 1, so a single-record
        # assertion holds no matter how the section groups - it would have gone
        # on passing after grouping landed while measuring nothing.
        html = _governance_html(_inherit_tag_group(4))
        card = re.search(
            r'metric-label">Policy-Enforced</div>\s*<div class="metric-number">(\d+)<',
            html)
        self.assertIsNotNone(card, "no Policy-Enforced metric card")
        self.assertEqual(int(card.group(1)), 4)
        # The heading counts resources, not rendered rows: after grouping the
        # four resources occupy one row, and the header must still describe the
        # estate rather than the layout.
        self.assertIn("Policy / System-Enforced Changes (4)", html)

    def test_the_governance_card_is_not_folded_into_total_issues(self):
        # These rows are deliberately outside COUNTED_TYPES. If the card ever
        # starts adding to the headline, "Total Issues" stops meaning
        # "things to act on" and the split loses its point.
        html = self._html()
        total = re.search(
            r'metric-label">Total Issues</div>\s*<div class="metric-number">(\d+)<', html)
        self.assertEqual(int(total.group(1)), tally_report(_report())["total_issues"])
        # ...and it renders after that card, where "not in Total Issues" reads
        # as a statement about the number above rather than a bare disclaimer.
        self.assertLess(html.index('metric-label">Total Issues'),
                        html.index('metric-label">Policy-Enforced'))

    def test_no_governance_card_on_an_estate_with_no_governance_rows(self):
        # A card reading 0 would be the only always-on card for a section that
        # is itself conditional.
        self.assertNotIn("Policy-Enforced", _render(policy_enforced_drifts=[]))


class AnUnattributedOutOfBandChangeStaysRedTests(unittest.TestCase):
    """The badge is derived from `origin`. Once an out-of-band change with no
    recorded actor stopped being labelled `manual_change`, it fell through to a
    neutral grey "Unknown" badge - visually downgrading a HIGH finding purely
    because Azure logged no caller. The row already carries the evidence.
    """

    def _badge(self, origin, category):
        from tools.html_report import _get_origin_badge
        return _get_origin_badge({"origin": origin, "category": category})

    def test_unattributed_out_of_band_is_not_greyed_out(self):
        badge = self._badge("unknown", "out_of_band")
        self.assertIn("origin-manual", badge)
        self.assertNotIn("origin-unknown", badge)

    def test_a_genuinely_unknown_origin_still_reads_unknown(self):
        # No category evidence either - the neutral badge is correct here.
        badge = self._badge("unknown", "unknown")
        self.assertIn("origin-unknown", badge)

    def test_named_manual_change_badge_is_unchanged(self):
        badge = self._badge("manual_change", "out_of_band")
        self.assertIn("origin-manual", badge)
        self.assertIn("Manual", badge)


if __name__ == "__main__":
    unittest.main()


class InternalPlumbingStaysOutOfTheReportTests(unittest.TestCase):
    """`_declared_in_rg` is how a drift row remembers which resource group its
    declaration targets, so orphan attribution survives the Phase 3 rename. It is
    pipeline plumbing, and it was appearing verbatim in the published report
    beside the human-readable note.

    The rule is general rather than one key: a details key starting with '_' is
    internal, and the report is the artifact a platform team reads.
    """

    def test_underscore_details_keys_are_stripped(self):
        from orchestration.reporting import _strip_internal_details
        report = {"drifts": [{"name": "x", "details": {
            "_declared_in_rg": "rg-logging",
            "orphaned_by_missing_resource_group": "rg-logging",
            "note": "kept",
        }}]}
        _strip_internal_details(report)
        details = report["drifts"][0]["details"]
        self.assertNotIn("_declared_in_rg", details)
        self.assertEqual(details["orphaned_by_missing_resource_group"], "rg-logging")
        self.assertEqual(details["note"], "kept")

    def test_every_bucket_is_cleaned(self):
        from orchestration.reporting import _strip_internal_details
        report = {b: [{"details": {"_declared_in_rg": "rg"}}]
                  for b in ("drifts", "policy_enforced_drifts", "ignored_drifts")}
        _strip_internal_details(report)
        for bucket in ("drifts", "policy_enforced_drifts", "ignored_drifts"):
            self.assertNotIn("_declared_in_rg", report[bucket][0]["details"], bucket)

    def test_rows_without_details_do_not_raise(self):
        from orchestration.reporting import _strip_internal_details
        _strip_internal_details({"drifts": [{"name": "x"}, {"name": "y", "details": None}]})


class ADeletedPlaceholderNamedResourceReachesTheReportTests(unittest.TestCase):
    """`property_drifts` feeds a report section of its own, and it was built from
    a bicep set that FILTERS OUT unresolvable-named declarations.

    That filter is right for property COMPARISON - you cannot diff a name that
    never resolved - but it also removed the row's existence. Live 2026-08-04:
    the deleted storage account rendered once (the drift table) where every
    literal-named finding rendered twice, so the section that lists missing
    resources simply did not mention it.

    Same shape as the rest of this round: a filter correct for its original
    purpose, reused as the input to something it was never checked against.
    """

    def _report(self):
        return {
            "drifts": [
                {"type": "Microsoft.Resources/resourceGroups", "name": "rg-logging",
                 "drift_type": "missing_in_azure", "details": {}},
                {"type": "Microsoft.Storage/storageAccounts", "name": "stla7m6et",
                 "drift_type": "missing_in_azure", "bicep_name_expression": "stl[86c9cbf6]",
                 "details": {"orphaned_by_missing_resource_group": "rg-logging"}},
                {"type": "Microsoft.KeyVault/vaults", "name": "kv-live",
                 "drift_type": "matched_unresolvable", "details": {}},
            ],
            "property_drifts": [
                {"resource_type": "Microsoft.Resources/resourceGroups",
                 "resource_name": "rg-logging", "bicep_name": "rg-logging",
                 "deployed_name": "", "drift_type": "missing",
                 "match_confidence": 1.0, "property_diffs": []},
            ],
        }

    def test_the_placeholder_named_deletion_is_added(self):
        from orchestration.reporting import _include_placeholder_deletions
        report = self._report()
        _include_placeholder_deletions(report)
        names = [r["resource_name"] for r in report["property_drifts"]]
        self.assertIn("stla7m6et", names,
                      "a deleted uniqueString-named resource never reached the report section")

    def test_it_keeps_the_bicep_expression_so_the_reader_can_find_it(self):
        from orchestration.reporting import _include_placeholder_deletions
        report = self._report()
        _include_placeholder_deletions(report)
        row = [r for r in report["property_drifts"] if r["resource_name"] == "stla7m6et"][0]
        self.assertEqual(row["drift_type"], "missing")
        self.assertEqual(row["bicep_name"], "stl[86c9cbf6]")

    def test_a_row_already_present_is_not_duplicated(self):
        from orchestration.reporting import _include_placeholder_deletions
        report = self._report()
        _include_placeholder_deletions(report)
        _include_placeholder_deletions(report)
        names = [r["resource_name"] for r in report["property_drifts"]]
        self.assertEqual(len(names), len(set(names)), f"duplicated rows: {names}")

    def test_matched_rows_are_not_added(self):
        from orchestration.reporting import _include_placeholder_deletions
        report = self._report()
        _include_placeholder_deletions(report)
        self.assertNotIn("kv-live", [r["resource_name"] for r in report["property_drifts"]])


class OneEventReadsAsOneEventTests(unittest.TestCase):
    """Drift rows were emitted in CREATION order, and an orphan is created a
    whole stage after the resource group that explains it. Live 2026-08-04:

        0.  missing  jacquidev-rg-logging   <- the cause      (Phase 1)
        1.  missing  jacquidev-law          <- orphan         (Phase 1)
        2-13.  six matched rows, six role assignments
        14. missing  jacquidevstla7m6et     <- orphan         (Phase 2)

    So the summary read as "logging RG and workspace deleted ... (six role
    assignments) ... and also a storage account" - the exact failure the orphan
    attribution exists to prevent. The link was in the data and nothing used it
    to order the output.
    """

    def _rows(self):
        return [
            {"type": "Microsoft.Resources/resourceGroups", "name": "rg-logging",
             "drift_type": "missing_in_azure", "details": {}},
            {"type": "Microsoft.OperationalInsights/workspaces", "name": "law",
             "drift_type": "missing_in_azure",
             "details": {"orphaned_by_missing_resource_group": "rg-logging"}},
            {"type": "Microsoft.Authorization/roleAssignments", "name": "Owner -> User:x",
             "drift_type": "extra_in_azure", "details": {}},
            {"type": "Microsoft.Resources/resourceGroups", "name": "NetworkWatcherRG",
             "drift_type": "extra_in_azure", "details": {}},
            {"type": "Microsoft.Storage/storageAccounts", "name": "stla7m6et",
             "drift_type": "missing_in_azure",
             "details": {"orphaned_by_missing_resource_group": "rg-logging"}},
        ]

    def _ordered(self):
        from orchestration.reporting import _group_orphans_with_their_cause
        report = {"drifts": self._rows()}
        _group_orphans_with_their_cause(report)
        return [r["name"] for r in report["drifts"]]

    def test_orphans_immediately_follow_their_resource_group(self):
        names = self._ordered()
        self.assertEqual(names[:3], ["rg-logging", "law", "stla7m6et"],
                         f"one deletion still reads as three unrelated ones: {names}")

    def test_nothing_is_lost_or_duplicated(self):
        before = sorted(r["name"] for r in self._rows())
        self.assertEqual(sorted(self._ordered()), before)

    def test_unrelated_rows_keep_their_relative_order(self):
        names = self._ordered()
        self.assertLess(names.index("Owner -> User:x"), names.index("NetworkWatcherRG"))

    def test_a_report_with_no_missing_group_is_untouched(self):
        from orchestration.reporting import _group_orphans_with_their_cause
        rows = [r for r in self._rows() if r["name"] != "rg-logging"]
        report = {"drifts": [dict(r) for r in rows]}
        _group_orphans_with_their_cause(report)
        self.assertEqual([r["name"] for r in report["drifts"]], [r["name"] for r in rows])
