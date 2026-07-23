"""App Service config expansion: config/web + config/appsettings, plus the
overlay of authoritative config/web values onto the site's siteConfig.

Resource Graph returns siteConfig as a ~93-key schema with nearly every value
NULL (ftpsState and minTlsVersion included), and the comparator skips null
deployed values to avoid false positives - so a template declaring siteConfig
INLINE on the site (the common bicep pattern) had those properties silently
skipped and NEVER compared. Fetch config/web and overlay non-null values so
transport/exposure settings are actually diffed.
"""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked

logger = logging.getLogger(__name__)


def _expand_appservice_config(resources: list[dict], token: str | None = None) -> list[dict]:
    """Expand App Service config children: config/web + config/appsettings.

    config/web (GET) carries the non-secret runtime surface: TLS minimum,
    ftpsState, http20Enabled, alwaysOn - portal setting flips are the canonical
    workload drift. App settings VALUES are secrets: the appsettings child is
    shaped with its raw properties here, and the comparator reduces both sides
    to KEY SETS (values are never compared or written to a report).
    """
    api = "2023-01-01"
    sites = [r for r in resources if (r.get("type") or "").lower() == "microsoft.web/sites"]
    if not sites:
        return []
    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for App Service config: {e}")
        return []

    def _call(url: str, method: str = "GET") -> dict:
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}", "Content-Length": "0"},
            method=method, data=b"" if method == "POST" else None,
        )
        with urlopen_checked(req, timeout=30) as resp:
            return _json.load(resp)

    children: list[dict] = []
    for site in sites:
        sid, sname = site.get("id", ""), site.get("name", "")
        if not sid or not sname:
            continue
        try:
            web = _call(f"https://management.azure.com{sid}/config/web?api-version={api}")
            web_props = web.get("properties", {}) or {}
            children.append({
                "type": "Microsoft.Web/sites/config", "name": f"{sname}/web",
                "location": None, "tags": {}, "sku": None, "kind": None,
                "properties": web_props,
                "id": web.get("id"), "resource_group": site.get("resource_group"),
            })
            # Overlay the authoritative config/web values onto the SITE's own
            # siteConfig. Nulls from the GET are not overlaid: they must not
            # clobber a value Resource Graph did resolve.
            site_props = site.get("properties")
            if not isinstance(site_props, dict):
                site_props = {}
                site["properties"] = site_props
            existing_cfg = site_props.get("siteConfig")
            merged = dict(existing_cfg) if isinstance(existing_cfg, dict) else {}
            merged.update({k: v for k, v in web_props.items() if v is not None})
            site_props["siteConfig"] = merged
        except Exception as e:
            logger.debug(f"Could not fetch config/web for {sname}: {e}")
        try:
            apps = _call(f"https://management.azure.com{sid}/config/appsettings/list?api-version={api}",
                         method="POST")
            children.append({
                "type": "Microsoft.Web/sites/config", "name": f"{sname}/appsettings",
                "location": None, "tags": {}, "sku": None, "kind": None,
                "properties": apps.get("properties", {}) or {},  # comparator reduces to keys
                "id": apps.get("id"), "resource_group": site.get("resource_group"),
            })
        except Exception as e:
            logger.debug(f"Could not fetch appsettings for {sname}: {e}")
    if children:
        logger.info(f"Expanded {len(children)} App Service config object(s)")
    return children
