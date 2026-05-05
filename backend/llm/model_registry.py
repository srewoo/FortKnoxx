"""Single source of truth for LLM model identifiers, capabilities, and pricing.

WHY: model IDs were previously hard-coded in three places (orchestrator,
api_client, server.py default, frontend). Drift caused requests to hit
deprecated models. Centralising here means one edit per quarterly model
refresh, and the orchestrator can ask "does this model accept a
temperature param?" instead of guessing.

Reasoning / thinking models (GPT-5, Claude extended-thinking variants,
Gemini deep-thinking) often reject the `temperature` parameter or
require a different request shape (e.g., OpenAI's
`max_completion_tokens` instead of `max_tokens`). This registry encodes
those quirks so callers stay simple.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModelSpec:
    id: str
    name: str
    description: str
    provider: str  # "openai" | "anthropic" | "gemini"
    family: str
    is_reasoning: bool = False
    supports_temperature: bool = True
    uses_max_completion_tokens: bool = False  # OpenAI reasoning quirk
    context_window: int = 128_000
    cost_per_1k_input_usd: float = 0.0
    cost_per_1k_output_usd: float = 0.0
    aliases: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------
# OpenAI — GPT-5 series.
# Reasoning models do not accept `temperature` and use
# `max_completion_tokens` rather than `max_tokens`.
# ---------------------------------------------------------------------
OPENAI_MODELS: list[ModelSpec] = [
    ModelSpec(
        id="gpt-5",
        name="GPT-5",
        description="OpenAI flagship reasoning model. Best quality, slowest.",
        provider="openai",
        family="gpt-5",
        is_reasoning=True,
        supports_temperature=False,
        uses_max_completion_tokens=True,
        context_window=400_000,
        cost_per_1k_input_usd=0.005,
        cost_per_1k_output_usd=0.015,
    ),
    ModelSpec(
        id="gpt-5-mini",
        name="GPT-5 Mini",
        description="Balanced reasoning model. Default for production.",
        provider="openai",
        family="gpt-5",
        is_reasoning=True,
        supports_temperature=False,
        uses_max_completion_tokens=True,
        context_window=400_000,
        cost_per_1k_input_usd=0.0015,
        cost_per_1k_output_usd=0.006,
    ),
    ModelSpec(
        id="gpt-5-nano",
        name="GPT-5 Nano",
        description="Fastest GPT-5 variant. Cheap, lower reasoning depth.",
        provider="openai",
        family="gpt-5",
        is_reasoning=True,
        supports_temperature=False,
        uses_max_completion_tokens=True,
        context_window=200_000,
        cost_per_1k_input_usd=0.00015,
        cost_per_1k_output_usd=0.0006,
    ),
]


# ---------------------------------------------------------------------
# Anthropic — Claude 4 series.
# These accept `temperature` even with extended thinking, but extended
# thinking restricts the valid range; clamp at call site if needed.
# ---------------------------------------------------------------------
ANTHROPIC_MODELS: list[ModelSpec] = [
    ModelSpec(
        id="claude-opus-4-7",
        name="Claude Opus 4.7",
        description="Anthropic flagship. Highest quality for code analysis.",
        provider="anthropic",
        family="claude-4",
        is_reasoning=True,
        supports_temperature=True,
        context_window=200_000,
        cost_per_1k_input_usd=0.015,
        cost_per_1k_output_usd=0.075,
    ),
    ModelSpec(
        id="claude-sonnet-4-6",
        name="Claude Sonnet 4.6",
        description="Balanced Claude model. Default for production.",
        provider="anthropic",
        family="claude-4",
        is_reasoning=False,
        supports_temperature=True,
        context_window=200_000,
        cost_per_1k_input_usd=0.003,
        cost_per_1k_output_usd=0.015,
    ),
    ModelSpec(
        id="claude-haiku-4-5",
        name="Claude Haiku 4.5",
        description="Fast Claude model. Cheap, lower latency.",
        provider="anthropic",
        family="claude-4",
        is_reasoning=False,
        supports_temperature=True,
        context_window=200_000,
        cost_per_1k_input_usd=0.0008,
        cost_per_1k_output_usd=0.004,
        aliases=("claude-haiku-4-5-20251001",),
    ),
]


# ---------------------------------------------------------------------
# Google — Gemini 3.1 series.
# ---------------------------------------------------------------------
GEMINI_MODELS: list[ModelSpec] = [
    ModelSpec(
        id="gemini-3.1-pro",
        name="Gemini 3.1 Pro",
        description="Google flagship. Strong long-context performance.",
        provider="gemini",
        family="gemini-3",
        is_reasoning=True,
        supports_temperature=True,
        context_window=2_000_000,
        cost_per_1k_input_usd=0.00125,
        cost_per_1k_output_usd=0.005,
    ),
    ModelSpec(
        id="gemini-3.1-flash",
        name="Gemini 3.1 Flash",
        description="Fast Gemini model. Default for production.",
        provider="gemini",
        family="gemini-3",
        is_reasoning=False,
        supports_temperature=True,
        context_window=1_000_000,
        cost_per_1k_input_usd=0.000075,
        cost_per_1k_output_usd=0.0003,
    ),
]


ALL_MODELS: list[ModelSpec] = OPENAI_MODELS + ANTHROPIC_MODELS + GEMINI_MODELS


# Build a lookup table that resolves both canonical IDs and aliases.
_BY_ID: dict[str, ModelSpec] = {}
for _m in ALL_MODELS:
    _BY_ID[_m.id] = _m
    for _alias in _m.aliases:
        _BY_ID[_alias] = _m


# Default model per provider — prefer the balanced "mid-tier" by default.
DEFAULT_MODEL_BY_PROVIDER: dict[str, str] = {
    "openai": "gpt-5-mini",
    "anthropic": "claude-sonnet-4-6",
    "gemini": "gemini-3.1-flash",
}


# Mapping from deprecated model IDs to current ones, used by both the
# backend (when reading saved settings) and the frontend (when reading
# user preferences from localStorage). Keeps existing users on a sane
# default after the upgrade without surprising them.
LEGACY_MODEL_MIGRATION: dict[str, str] = {
    # OpenAI
    "gpt-4o": "gpt-5-mini",
    "gpt-4o-mini": "gpt-5-mini",
    "gpt-4-turbo": "gpt-5-mini",
    "gpt-4": "gpt-5-mini",
    "gpt-3.5-turbo": "gpt-5-nano",
    # Anthropic
    "claude-3-5-sonnet-20241022": "claude-sonnet-4-6",
    "claude-3-7-sonnet-20250219": "claude-sonnet-4-6",
    "claude-sonnet-4-20250514": "claude-sonnet-4-6",
    "claude-4-sonnet-20250514": "claude-sonnet-4-6",
    "claude-3-haiku-20240307": "claude-haiku-4-5",
    # Gemini
    "gemini-pro": "gemini-3.1-flash",
    "gemini-1.5-pro": "gemini-3.1-pro",
    "gemini-1.5-flash": "gemini-3.1-flash",
    "gemini-2.0-flash": "gemini-3.1-flash",
    "gemini-2.0-flash-exp": "gemini-3.1-flash",
}


def get_model(model_id: str) -> ModelSpec | None:
    """Return the ModelSpec for a model ID (canonical or alias).

    Returns None for unknown IDs — the caller decides whether to fall
    back to a default or surface an error.
    """
    if not model_id:
        return None
    return _BY_ID.get(model_id)


def resolve_model_id(model_id: str | None, provider: str) -> str:
    """Resolve any input — current ID, alias, legacy ID, or None — to a
    canonical model ID for the given provider.

    Order:
      1. Canonical ID or alias → return as-is.
      2. Legacy ID → map via LEGACY_MODEL_MIGRATION.
      3. None / unknown → provider default.
    """
    if model_id and model_id in _BY_ID:
        return _BY_ID[model_id].id
    if model_id and model_id in LEGACY_MODEL_MIGRATION:
        return LEGACY_MODEL_MIGRATION[model_id]
    return DEFAULT_MODEL_BY_PROVIDER.get(provider.lower(), DEFAULT_MODEL_BY_PROVIDER["anthropic"])


def list_models(provider: str) -> list[dict[str, str]]:
    """Frontend-facing model list for a provider."""
    pool = {
        "openai": OPENAI_MODELS,
        "anthropic": ANTHROPIC_MODELS,
        "gemini": GEMINI_MODELS,
    }.get(provider.lower(), [])
    return [
        {
            "id": m.id,
            "name": m.name,
            "description": m.description,
            "is_reasoning": m.is_reasoning,
        }
        for m in pool
    ]


def supports_temperature(model_id: str) -> bool:
    """True if the model accepts a `temperature` parameter."""
    spec = get_model(model_id)
    return spec.supports_temperature if spec else True


def uses_max_completion_tokens(model_id: str) -> bool:
    """True if the model requires OpenAI's `max_completion_tokens` field."""
    spec = get_model(model_id)
    return spec.uses_max_completion_tokens if spec else False


def is_reasoning_model(model_id: str) -> bool:
    spec = get_model(model_id)
    return bool(spec and spec.is_reasoning)


def get_pricing(model_id: str) -> tuple[float, float]:
    """Return (input_cost_per_1k, output_cost_per_1k) USD."""
    spec = get_model(model_id)
    if spec is None:
        return (0.0, 0.0)
    return (spec.cost_per_1k_input_usd, spec.cost_per_1k_output_usd)
