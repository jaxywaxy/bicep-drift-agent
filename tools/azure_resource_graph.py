"""Azure Resource Graph client for querying resources via KQL."""

import os
import subprocess
import json


class ResourceGraphClient:
    """Client for querying Azure resources using KQL."""

    def query(self, query: str, subscriptions: list = None):
        """
        Execute a KQL query against Azure resources using Azure CLI.

        Args:
            query: KQL query string
            subscriptions: Optional list of subscription IDs. Uses current subscription if not provided.

        Returns:
            List of query results
        """
        if subscriptions is None:
            sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
            subscriptions = [sub_id] if sub_id else []

        try:
            # Use Azure CLI to query Resource Graph
            cmd = ["az", "graph", "query", "-q", query]
            if subscriptions:
                cmd.extend(["-s"] + subscriptions)

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            return data.get("data", [])
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Resource Graph query failed: {e}")
