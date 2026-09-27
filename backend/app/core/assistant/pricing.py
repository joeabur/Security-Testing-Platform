"""Estimating what one provider call costs, before it is sent.

`GatedTransport`/`BudgetTracker` (app/core/scope/budgets.py) can only enforce
a cost ceiling on numbers callers actually give it. Until this module
existed, `openai_compatible.py` passed `estimated_cost_usd=0.0` on every
call — not a conservative estimate, an absent one — so `PROVIDER_BUDGETS.
max_estimated_cost_usd` (egress.py) never actually stopped anything: the
running total it compared against never moved. This is what makes that
number real.

Pricing is necessarily approximate — providers change list prices and this
platform has no live pricing feed. The bias is deliberate: an unrecognized
model gets `DEFAULT_USD_PER_1K_TOKENS`, a middle-of-the-road rate, rather
than free. Overcounting an unknown model wastes a little of the budget
early; undercounting it (treating it as free) is the failure that lets
spend run away unnoticed, which is the one this exists to prevent.
"""

from __future__ import annotations

# USD per 1,000 tokens, blended (sent + received priced the same) for
# simplicity — the budget this guards is a safety ceiling, not a billing
# reconciliation, so a single blended rate per model is precise enough.
# Keyed on a case-insensitive substring of the configured model name, since
# operators write model names inconsistently ("gpt-4o", "gpt-4o-2024-08-06").
_KNOWN_USD_PER_1K_TOKENS: dict[str, float] = {
    "gpt-4o-mini": 0.00026,
    "gpt-4o": 0.0075,
    "gpt-4-turbo": 0.02,
    "gpt-4": 0.045,
    "gpt-3.5": 0.0015,
    "claude-3-opus": 0.045,
    "claude-3-5-sonnet": 0.009,
    "claude-3-sonnet": 0.009,
    "claude-3-haiku": 0.00075,
    "claude": 0.009,
    "gemini-1.5-pro": 0.00875,
    "gemini-1.5-flash": 0.0002,
    "llama": 0.0009,
    "mixtral": 0.0009,
}

# What an unrecognized model is priced at. Deliberately not the cheapest
# entry in the table above — see the module docstring.
DEFAULT_USD_PER_1K_TOKENS = 0.01

# ~4 characters per token is the standard rough estimate for English text
# tokenized by a BPE-family tokenizer; good enough for a pre-flight budget
# check, which only needs to be in the right order of magnitude.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN)


def price_per_1k_tokens(model: str) -> float:
    lowered = model.lower()
    for needle, price in _KNOWN_USD_PER_1K_TOKENS.items():
        if needle in lowered:
            return price
    return DEFAULT_USD_PER_1K_TOKENS


def estimate_cost_usd(model: str, *, tokens_sent: int, tokens_received: int) -> float:
    rate = price_per_1k_tokens(model)
    return (tokens_sent + tokens_received) / 1000 * rate
