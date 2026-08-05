"""
Phase 2: Agent-based drift analysis and remediation.

`DriftAgent` is the LLM orchestrator - it owns the LLM provider (see
`agent/llm/`, selected by DRIFT_LLM_PROVIDER, default anthropic), the
conversation history, and the analyze / follow-up / recommend calls. The work it
composes lives in mixins it inherits, each independently testable:

- classification.DriftClassifier - deterministic Drift -> DriftFinding (no LLM)
- live_context.LiveContextMixin   - enrich findings with live Azure state
- prompts.PromptsMixin            - system prompt + drift-context serialisation

Finding types (severity/category/action enums, DriftFinding) live in findings.py;
usage/cost accounting in usage.py. All re-exported here for backwards-compatible
imports.
"""

import json
import logging
import os
from dataclasses import replace

from agent.llm import get_provider

from tools.models import DriftReport

from .usage import AgentUsage
from .findings import (  # noqa: F401  (re-exported for callers/tests)
    DriftSeverity, DriftCategory, RemediationAction, DriftFinding,
)
from .classification import DriftClassifier
from .live_context import LiveContextMixin
from .prompts import PromptsMixin

logger = logging.getLogger(__name__)




class DriftAgent(DriftClassifier, LiveContextMixin, PromptsMixin):
    """Uses Claude to analyse Azure/Bicep drift and suggest remediation."""








    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_drift_items_for_prompt: int = 100,
        provider=None,
    ):
        """
        Initialise drift agent.

        Args:
            api_key: Provider API key. Defaults to the provider's own env var.
            model: Model id. Defaults to DRIFT_AGENT_MODEL env var, then the
                PROVIDER's default - so selecting a provider does not also
                require naming one of its models.
            provider: Pre-built LLM provider (tests, or an embedder choosing its
                own). Defaults to DRIFT_LLM_PROVIDER, which defaults to
                anthropic - so existing deployments are unaffected.
            max_drift_items_for_prompt: Safety limit to prevent overly large prompts.
        """
        self.provider = provider or get_provider(api_key=api_key)
        # The default belongs to the PROVIDER - a Claude model id on this class
        # was a leftover from when there was only one vendor.
        self.model = (model or os.environ.get("DRIFT_AGENT_MODEL")
                      or self.provider.default_model)
        self.max_drift_items_for_prompt = max_drift_items_for_prompt
        self.conversation_history: list[dict[str, str]] = []
        self.usage = AgentUsage()

    def _create_message(self, **kwargs):
        """Every LLM call goes through here, so per-run usage/cost accumulates
        and no caller above this line sees a vendor response shape."""
        response = self.provider.complete(model=self.model, **kwargs)
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.usage.record(self.model, usage)
            logger.debug(
                f"LLM call {self.usage.calls}: "
                f"{getattr(usage, 'input_tokens', 0)} in / {getattr(usage, 'output_tokens', 0)} out"
            )
        return response

    def analyze_drift(self, drift_report: DriftReport) -> str:
        """
        Analyse drift report and return a human-readable recommendation.

        Args:
            drift_report: Drift analysis from Phase 1.

        Returns:
            Human-readable analysis and recommendations.
        """
        # matched_unresolvable entries are NOT drift - they record that a
        # runtime-named resource was reconciled to its deployed counterpart.
        # Feeding them to the analysis as findings both inflates the prompt
        # (they dominated real estates ~30:3) and degrades the output: the
        # model spends its answer caveating "unresolved" rows instead of
        # analysing the actionable drift. They are reduced to a count.
        all_drifts = drift_report.drifts or []
        actionable = [d for d in all_drifts if d.drift_type != "matched_unresolvable"]
        reconciled_count = len(all_drifts) - len(actionable)
        if reconciled_count:
            drift_report = replace(drift_report, drifts=actionable)

        findings = self._build_findings(drift_report)
        summary = self._build_summary(drift_report, findings)
        context = self._format_drift_context(
            drift_report, findings, summary, reconciled_count=reconciled_count
        )

        self.conversation_history = [
            {
                "role": "user",
                "content": context,
            }
        ]

        # 3000 truncated a 9-drift report mid-sentence in the remediation plan
        # (live run 2026-07-26), and the plan is the part operators act on. The
        # analysis scales with drift count, so the cap has to clear a real
        # multi-drift estate, not the clean-estate case.
        response = self._create_message(
            max_tokens=8000,
            system=self._get_system_prompt(),
            messages=self.conversation_history,
        )

        analysis = response.text.strip()
        if response.truncated:
            logger.warning(
                "Claude analysis hit the max_tokens cap and is truncated; "
                "the remediation plan may be incomplete."
            )

        self.conversation_history.append(
            {
                "role": "assistant",
                "content": analysis,
            }
        )

        return analysis

    def ask_followup(self, question: str) -> str:
        """
        Ask a follow-up question about the drift analysis.

        Maintains conversation history for context.
        """
        self.conversation_history.append(
            {
                "role": "user",
                "content": question,
            }
        )

        response = self._create_message(
            max_tokens=1500,
            system=self._get_system_prompt(),
            messages=self.conversation_history,
        )

        answer = response.text.strip()

        self.conversation_history.append(
            {
                "role": "assistant",
                "content": answer,
            }
        )

        return answer

    def get_drift_recommendation(
        self,
        resource_type: str,
        resource_name: str,
        drift_type: str,
        details: dict | None = None,
        resource_id: str | None = None,
    ) -> str:
        """
        Get a specific remediation recommendation for a single drift item.

        This now uses the same local classification logic as full analysis.
        """
        pseudo_drift = self._make_pseudo_drift(
            resource_type=resource_type,
            resource_name=resource_name,
            drift_type=drift_type,
            details=details or {},
            resource_id=resource_id,
        )

        finding = self._classify_drift(pseudo_drift)

        prompt = f"""
Given this Azure/Bicep drift finding, provide a concise remediation recommendation.

Resource type: {finding.resource_type}
Resource name: {finding.resource_name}
Resource ID: {finding.resource_id or "unknown"}
Drift type: {finding.drift_type}
Severity: {finding.severity}
Category: {finding.category}
Recommended action: {finding.recommended_action}
Classification reason: {finding.reason}
Details: {json.dumps(finding.details or {}, indent=2)}

Respond with:
1. Recommended action
2. Why
3. Verification command or check, if applicable
"""

        response = self._create_message(
            max_tokens=500,
            system=(
                "You are an Azure infrastructure expert. "
                "Provide brief, actionable remediation recommendations. "
                "Do not invent facts that are not present in the input."
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        return response.text.strip()




















