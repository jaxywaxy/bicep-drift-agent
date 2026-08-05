"""
agent/usage.py

LLM API usage accounting + cost estimation for one drift-check run.
Pricing is model-prefix keyed; a missing model means tokens are known but
dollars are not (returns None rather than guessing).
"""

from dataclasses import dataclass, field
from typing import Any



# USD per million tokens (input, output), keyed by model-id prefix so dated
# full IDs ('claude-haiku-4-5-20251001') match their alias row. Cache reads
# bill at ~0.1x input, cache writes (5m TTL) at 1.25x input. Prices move -
# treat a missing model as "tokens known, dollars unknown" rather than guess.
MODEL_PRICING_PER_MTOK = {
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25


@dataclass
class AgentUsage:
    """Accumulated Claude API usage for one drift-check run."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    _models: list[str] = field(default_factory=list)

    def record(self, model: str, usage: Any) -> None:
        """Add one response's usage block (tolerates absent cache fields)."""
        self.calls += 1
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0
        self.cache_creation_input_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
        self.cache_read_input_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
        if model not in self._models:
            self._models.append(model)

    @staticmethod
    def _pricing_for(model: str):
        for prefix, prices in MODEL_PRICING_PER_MTOK.items():
            if model.startswith(prefix):
                return prices
        return None

    def cost_usd(self) -> float | None:
        """Estimated USD cost, or None when any model used has no price row."""
        if not self._models:
            return 0.0
        total = 0.0
        # All calls in a run use one model in practice; if several were used we
        # can't attribute tokens per model, so price only the single-model case.
        if len(self._models) > 1:
            return None
        prices = self._pricing_for(self._models[0])
        if prices is None:
            return None
        in_price, out_price = prices
        total += self.input_tokens * in_price / 1_000_000
        total += self.output_tokens * out_price / 1_000_000
        total += self.cache_read_input_tokens * in_price * CACHE_READ_MULTIPLIER / 1_000_000
        total += self.cache_creation_input_tokens * in_price * CACHE_WRITE_MULTIPLIER / 1_000_000
        return total

    def to_dict(self) -> dict[str, Any]:
        cost = self.cost_usd()
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "models": list(self._models),
            "estimated_cost_usd": round(cost, 6) if cost is not None else None,
        }

    def summary(self) -> str:
        cost = self.cost_usd()
        cost_str = f"${cost:.4f}" if cost is not None else "unknown (no price for model)"
        return (
            f"{self.calls} LLM call(s), {self.input_tokens} in / "
            f"{self.output_tokens} out tokens"
            + (f" (+{self.cache_read_input_tokens} cache-read)" if self.cache_read_input_tokens else "")
            + f", estimated cost {cost_str}"
        )
