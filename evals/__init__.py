"""Narrative evaluation: mechanical checks on what the LLM actually wrote.

`evals/checks.py` is pure and deterministic, so it runs in the normal test
suite. `evals/run.py` makes real LLM calls and is run on demand.
"""
