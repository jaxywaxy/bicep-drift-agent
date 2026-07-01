"""Azure Resource Graph client for querying resources via KQL."""

from azure.mgmt.resourcegraph import ResourceGraphManagementClient
from azure.mgmt.resourcegraph.models import QueryRequest
from azure.identity import DefaultAzureCredential


class ResourceGraphClient:
    """Client for querying Azure resources using KQL."""

    def __init__(self):
        """Initialize Resource Graph client."""
        self.credential = DefaultAzureCredential()
        self.client = ResourceGraphManagementClient(self.credential)

    def query(self, query: str, subscriptions: list = None):
        """
        Execute a KQL query against Azure resources.

        Args:
            query: KQL query string
            subscriptions: Optional list of subscription IDs. Uses current subscription if not provided.

        Returns:
            List of query results
        """
        import os

        if subscriptions is None:
            sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
            subscriptions = [sub_id] if sub_id else []

        request = QueryRequest(query=query, subscriptions=subscriptions)
        response = self.client.resources(request)
        return response.data if response.data else []
