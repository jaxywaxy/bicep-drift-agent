"""
tools/property_drift/extractor.py

Extract the comparable property surface from a Bicep-compiled or Azure-live
resource. Both extractors pick the same set of top-level ARM keys plus the
resource-specific `properties` bag; the two exist mainly to make the source
side obvious at the call site.
"""

from typing import Any


class PropertyExtractor:
    """Extract properties from resources."""

    @staticmethod
    def extract_bicep_properties(resource: dict) -> dict[str, Any]:
        """Extract properties from a Bicep-compiled ARM resource."""
        properties = {}

        # Top-level properties (skip apiVersion — it's ARM template metadata, not a deployment property)
        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "location" in resource:
            properties["location"] = resource["location"]
        if "tags" in resource:
            properties["tags"] = resource["tags"]
        if "sku" in resource:
            properties["sku"] = resource["sku"]
        if "kind" in resource:
            properties["kind"] = resource["kind"]
        # Availability zones: a top-level ARM key like location/sku, NOT part of
        # `properties`. Every layer that rebuilds a resource dict from a fixed
        # key list has to carry it or zone drift is silently unobservable - this
        # extractor is the LAST of three such layers (see also normalize_resource
        # and the Resource Graph row builder).
        if "zones" in resource:
            properties["zones"] = resource["zones"]

        # Resource-specific properties
        if "properties" in resource:
            properties["properties"] = resource["properties"]

        return properties

    @staticmethod
    def extract_azure_properties(resource: dict) -> dict[str, Any]:
        """Extract properties from an Azure-deployed resource."""
        properties = {}

        if "name" in resource:
            properties["name"] = resource["name"]
        if "type" in resource:
            properties["type"] = resource["type"]
        if "id" in resource:
            properties["id"] = resource["id"]
        if "location" in resource:
            properties["location"] = resource["location"]
        if "tags" in resource:
            properties["tags"] = resource["tags"]
        if "sku" in resource:
            properties["sku"] = resource["sku"]
        if "kind" in resource:
            properties["kind"] = resource["kind"]
        if "zones" in resource:  # top-level ARM key; see the bicep-side note above
            properties["zones"] = resource["zones"]

        if "properties" in resource:
            properties["properties"] = resource["properties"]

        return properties
