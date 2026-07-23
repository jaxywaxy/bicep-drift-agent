"""Azure Container Instance container-group normalisation.

Azure injects runtime-only fields into each container that Bicep never declares
and returns cpu/memoryInGB as floats where Bicep uses ints. We strip the noise
and coerce whole-number requests to int in place.
"""


def _normalize_aci_container_groups(resources: list[dict]) -> None:
    """Normalize Container Instance 'properties.containers' in-place to avoid false drift."""
    RUNTIME_ONLY = ("instanceView",)
    DROP_IF_EMPTY = ("configMap", "environmentVariables", "ports", "volumeMounts", "command")

    for r in resources:
        if (r.get("type") or "").lower() != "microsoft.containerinstance/containergroups":
            continue
        props = r.get("properties")
        if not isinstance(props, dict):
            continue
        containers = props.get("containers")
        if not isinstance(containers, list):
            continue
        for c in containers:
            cprops = c.get("properties") if isinstance(c, dict) else None
            if not isinstance(cprops, dict):
                continue
            for key in RUNTIME_ONLY:
                cprops.pop(key, None)
            for key in DROP_IF_EMPTY:
                if key in cprops and cprops[key] in ([], {}, None):
                    cprops.pop(key, None)
            # configMap comes back as {"keyValuePairs": {}} when unset - drop that too
            cm = cprops.get("configMap")
            if isinstance(cm, dict) and not cm.get("keyValuePairs"):
                cprops.pop("configMap", None)
            requests = (cprops.get("resources") or {}).get("requests")
            if isinstance(requests, dict):
                for key in ("cpu", "memoryInGB"):
                    v = requests.get(key)
                    if isinstance(v, float) and v.is_integer():
                        requests[key] = int(v)
