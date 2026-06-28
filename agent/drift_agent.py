"""
Phase 2: Agent-based drift analysis and remediation.

Uses Claude to reason about drift, classify severity, and suggest fixes.
"""

import json
from anthropic import Anthropic

from tools.models import DriftReport, Drift


class DriftAgent:
    """Uses Claude to analyze drift and suggest remediation."""

    def __init__(self, api_key: str = None):
        """Initialize drift agent with Anthropic client."""
        self.client = Anthropic(api_key=api_key)
        self.model = "claude-opus-4-8"
        self.conversation_history = []

    def analyze_drift(self, drift_report: DriftReport) -> str:
        """
        Analyze drift report using Claude.

        Args:
            drift_report: The drift analysis from Phase 1

        Returns:
            Human-readable analysis and recommendations
        """
        # Build the context for Claude
        context = self._format_drift_context(drift_report)

        # First message: provide the drift data
        self.conversation_history = [
            {
                "role": "user",
                "content": context
            }
        ]

        # Get Claude's analysis
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=self._get_system_prompt(),
            messages=self.conversation_history
        )

        analysis = response.content[0].text
        self.conversation_history.append({
            "role": "assistant",
            "content": analysis
        })

        return analysis

    def ask_followup(self, question: str) -> str:
        """
        Ask a follow-up question about the drift analysis.

        Maintains conversation history for context.

        Args:
            question: Follow-up question

        Returns:
            Claude's response
        """
        self.conversation_history.append({
            "role": "user",
            "content": question
        })

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            system=self._get_system_prompt(),
            messages=self.conversation_history
        )

        answer = response.content[0].text
        self.conversation_history.append({
            "role": "assistant",
            "content": answer
        })

        return answer

    def get_drift_recommendation(
        self,
        resource_type: str,
        resource_name: str,
        drift_type: str,
        details: dict = None,
    ) -> str:
        """
        Get a specific remediation recommendation for a single drift item.

        Args:
            resource_type: Azure resource type (e.g., Microsoft.Storage/storageAccounts)
            resource_name: Resource name
            drift_type: Type of drift (missing, extra, modified)
            details: Drift details dict

        Returns:
            Remediation recommendation
        """
        prompt = f"""Given this specific infrastructure drift, provide a concise remediation recommendation (1-2 sentences):

**Resource:** {resource_type} / {resource_name}
**Drift Type:** {drift_type}
{f"**Details:** {json.dumps(details)}" if details else ""}

Respond with only the actionable recommendation."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=300,
            system="You are an Azure infrastructure expert. Provide brief, actionable remediation recommendations.",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text.strip()

    @staticmethod
    def _get_system_prompt() -> str:
        """System prompt for drift analysis."""
        return """You are an expert Azure infrastructure engineer analyzing Bicep deployment drift.

Your role is to:
1. Understand why drift exists between desired (Bicep) and actual (Azure) state
2. Classify severity (critical infrastructure missing vs. config drift)
3. Explain what happened and why
4. Suggest specific remediation steps
5. Provide confidence assessment given data quality

Key insights:
- Landing zone templates use nested modules that hide real resources
- Unresolved expressions like `format('vnet-{0}', environment)` are normal in compiled ARM
- Resource groups defined in Bicep may be deployed at subscription scope
- System-managed resources (managed disks) always appear as "extra"
- VMs without explicit Bicep definitions might be expected infrastructure

Be concise but thorough. Focus on actionable insights."""

    @staticmethod
    def _format_drift_context(drift_report: DriftReport) -> str:
        """Format drift report for Claude analysis."""
        missing = [d for d in (drift_report.drifts or []) if "missing" in d.drift_type]
        extra = [d for d in (drift_report.drifts or []) if "extra" in d.drift_type]
        modified = [d for d in (drift_report.drifts or []) if "modified" in d.drift_type]

        context = f"""# Bicep Drift Analysis Request

## Deployment Context
- **Bicep File:** {drift_report.bicep_file}
- **Resource Group:** {drift_report.resource_group}
- **Parameters:** {json.dumps(drift_report.parameters or {})}

## Drift Summary
- **Missing (in Bicep, not in Azure):** {len(missing)}
- **Extra (in Azure, not in Bicep):** {len(extra)}
- **Modified:** {len(modified)}
- **Total Issues:** {drift_report.total_drift}

## Missing Resources (Desired but not deployed)
"""
        for drift in missing:
            context += f"\n- **{drift.resource_type}** / {drift.resource_name}"
            if drift.details:
                context += f"\n  Details: {json.dumps(drift.details)}"

        context += "\n\n## Extra Resources (Deployed but not in template)\n"
        for drift in extra:
            context += f"\n- **{drift.resource_type}** / {drift.resource_name}"
            if drift.details:
                context += f"\n  Details: {json.dumps(drift.details)}"

        if modified:
            context += "\n\n## Modified Resources\n"
            for drift in modified:
                context += f"\n- **{drift.resource_type}** / {drift.resource_name}"
                if drift.details:
                    context += f"\n  Changed: {json.dumps(drift.details)}"

        context += """

## Questions to Answer
1. Is this drift expected or problematic?
2. What's the root cause? (template mismatch, manual deployments, scope issues, etc.)
3. For each missing resource: Should it be deployed? How?
4. For each extra resource: Should it be deleted or added to template?
5. What's the confidence level given the data quality?
6. What's the recommended fix?

Provide a structured analysis that an infrastructure team can act on."""

        return context
