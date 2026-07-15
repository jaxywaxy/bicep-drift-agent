"""
App Service / Function App siteConfig drift must be visible AND critical.

FALSE NEGATIVE found live: a function app's ftpsState was flipped
FtpsOnly -> AllAllowed (FTP credentials in PLAINTEXT while the site still
reports httpsOnly=true) and the scan reported NO DRIFT AT ALL.

Mechanism: Resource Graph returns Microsoft.Web/sites siteConfig as a ~93-key
schema with nearly every value NULL (ftpsState and minTlsVersion included).
The comparator skips null deployed values to avoid false positives, so a
template declaring siteConfig INLINE on the site - the common bicep pattern -
had every one of those properties silently skipped. The real values were
already being fetched into the config/web child and simply never compared.

Fix: get_live_state overlays the authoritative config/web GET onto the site's
siteConfig; ftpsState/minTlsVersion are now critical in BOTH shapes (inline on
the site, and on the config/web child).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.property_drift import PropertyComparator


def _site(ftps="FtpsOnly", tls="1.2", inline=True):
    cfg = {"minTlsVersion": tls, "ftpsState": ftps, "http20Enabled": True}
    if inline:
        return {"type": "Microsoft.Web/sites", "name": "func-drift",
                "properties": {"httpsOnly": True, "siteConfig": cfg}}
    return {"type": "Microsoft.Web/sites/config", "name": "func-drift/web",
            "properties": cfg}


def _sev(bicep, live, path):
    d = [x for x in PropertyComparator.compare_properties(bicep, live)
         if x.property_path == path]
    return d[0].severity if d else None


class SiteConfigSeverityTests(unittest.TestCase):
    def test_inline_ftps_state_drift_is_critical(self):
        # The live false negative, once the config/web overlay makes it visible.
        self.assertEqual(
            _sev(_site(), _site(ftps="AllAllowed"), "properties.siteConfig.ftpsState"),
            "critical")

    def test_web_child_ftps_state_drift_is_critical(self):
        self.assertEqual(
            _sev(_site(inline=False), _site(ftps="AllAllowed", inline=False),
                 "properties.ftpsState"),
            "critical")

    def test_inline_min_tls_drift_is_critical(self):
        self.assertEqual(
            _sev(_site(), _site(tls="1.0"), "properties.siteConfig.minTlsVersion"),
            "critical")

    def test_web_child_min_tls_drift_is_critical(self):
        self.assertEqual(
            _sev(_site(inline=False), _site(tls="1.0", inline=False),
                 "properties.minTlsVersion"),
            "critical")

    def test_operational_siteconfig_stays_warning(self):
        # Don't inflate everything: http20Enabled is not a security control.
        bicep, live = _site(), _site()
        live["properties"]["siteConfig"]["http20Enabled"] = False
        self.assertEqual(_sev(bicep, live, "properties.siteConfig.http20Enabled"),
                         "warning")

    def test_identical_siteconfig_no_drift(self):
        paths = [x.property_path for x in
                 PropertyComparator.compare_properties(_site(), _site())]
        self.assertNotIn("properties.siteConfig.ftpsState", paths)
        self.assertNotIn("properties.siteConfig.minTlsVersion", paths)


class SiteConfigOverlayTests(unittest.TestCase):
    """The overlay is what makes the above comparable at all: without it the
    live siteConfig is all-nulls and every declared property is skipped."""

    def test_null_live_siteconfig_hides_drift_without_overlay(self):
        bicep = _site(ftps="FtpsOnly")
        live_arg_nulls = {"type": "Microsoft.Web/sites", "name": "func-drift",
                          "properties": {"httpsOnly": True,
                                         "siteConfig": {"ftpsState": None,
                                                        "minTlsVersion": None,
                                                        "http20Enabled": True}}}
        # Reproduces the false negative: nothing to compare.
        self.assertIsNone(_sev(bicep, live_arg_nulls, "properties.siteConfig.ftpsState"))

    def test_overlay_of_web_child_makes_drift_visible(self):
        bicep = _site(ftps="FtpsOnly")
        live = {"type": "Microsoft.Web/sites", "name": "func-drift",
                "properties": {"httpsOnly": True,
                               "siteConfig": {"ftpsState": None, "minTlsVersion": None,
                                              "http20Enabled": True}}}
        web_props = {"ftpsState": "AllAllowed", "minTlsVersion": "1.2",
                     "someUnsetThing": None}
        # Same overlay get_live_state performs: non-null GET values win.
        cfg = dict(live["properties"]["siteConfig"])
        cfg.update({k: v for k, v in web_props.items() if v is not None})
        live["properties"]["siteConfig"] = cfg
        self.assertEqual(_sev(bicep, live, "properties.siteConfig.ftpsState"), "critical")


if __name__ == "__main__":
    unittest.main()
