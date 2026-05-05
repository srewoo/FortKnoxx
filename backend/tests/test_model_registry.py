"""Tests for llm.model_registry — the source of truth for model IDs."""

from __future__ import annotations

import pytest

from llm.model_registry import (
    ALL_MODELS,
    ANTHROPIC_MODELS,
    DEFAULT_MODEL_BY_PROVIDER,
    GEMINI_MODELS,
    LEGACY_MODEL_MIGRATION,
    OPENAI_MODELS,
    get_model,
    get_pricing,
    is_reasoning_model,
    list_models,
    resolve_model_id,
    supports_temperature,
    uses_max_completion_tokens,
)


class TestRegistryShape:
    def test_each_provider_has_at_least_one_model(self):
        assert OPENAI_MODELS
        assert ANTHROPIC_MODELS
        assert GEMINI_MODELS

    def test_defaults_resolve_to_real_models(self):
        for provider, model_id in DEFAULT_MODEL_BY_PROVIDER.items():
            spec = get_model(model_id)
            assert spec is not None, f"Default for {provider} ({model_id}) is missing"
            assert spec.provider == provider

    def test_all_models_have_costs(self):
        for spec in ALL_MODELS:
            assert spec.cost_per_1k_input_usd >= 0
            assert spec.cost_per_1k_output_usd >= 0

    def test_no_duplicate_ids(self):
        seen: set[str] = set()
        for spec in ALL_MODELS:
            assert spec.id not in seen, f"Duplicate model id: {spec.id}"
            seen.add(spec.id)


class TestResolveModelId:
    @pytest.mark.parametrize(
        "legacy,expected",
        [
            ("gpt-4o-mini", "gpt-5-mini"),
            ("gpt-4", "gpt-5-mini"),
            ("gpt-3.5-turbo", "gpt-5-nano"),
            ("claude-3-5-sonnet-20241022", "claude-sonnet-4-6"),
            ("claude-3-7-sonnet-20250219", "claude-sonnet-4-6"),
            ("claude-3-haiku-20240307", "claude-haiku-4-5"),
            ("gemini-pro", "gemini-3.1-flash"),
            ("gemini-1.5-pro", "gemini-3.1-pro"),
            ("gemini-2.0-flash", "gemini-3.1-flash"),
        ],
    )
    def test_legacy_ids_migrate_to_current(self, legacy, expected):
        assert legacy in LEGACY_MODEL_MIGRATION
        assert resolve_model_id(legacy, "ignored") == expected

    def test_canonical_id_returns_self(self):
        assert resolve_model_id("gpt-5-mini", "openai") == "gpt-5-mini"
        assert resolve_model_id("claude-sonnet-4-6", "anthropic") == "claude-sonnet-4-6"

    def test_alias_resolves_to_canonical(self):
        # claude-haiku-4-5-20251001 is an alias for claude-haiku-4-5.
        assert resolve_model_id("claude-haiku-4-5-20251001", "anthropic") == "claude-haiku-4-5"

    def test_none_falls_back_to_provider_default(self):
        assert resolve_model_id(None, "openai") == DEFAULT_MODEL_BY_PROVIDER["openai"]
        assert resolve_model_id(None, "anthropic") == DEFAULT_MODEL_BY_PROVIDER["anthropic"]
        assert resolve_model_id(None, "gemini") == DEFAULT_MODEL_BY_PROVIDER["gemini"]

    def test_unknown_id_falls_back_to_provider_default(self):
        assert resolve_model_id("totally-made-up-model", "openai") == DEFAULT_MODEL_BY_PROVIDER["openai"]


class TestThinkingModelHandling:
    def test_gpt5_series_rejects_temperature(self):
        for model_id in ("gpt-5", "gpt-5-mini", "gpt-5-nano"):
            assert not supports_temperature(
                model_id
            ), f"{model_id} is a reasoning model and must not advertise temperature support"
            assert uses_max_completion_tokens(model_id)
            assert is_reasoning_model(model_id)

    def test_claude_4_accepts_temperature(self):
        for model_id in ("claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5"):
            assert supports_temperature(model_id)
            assert not uses_max_completion_tokens(model_id)

    def test_gemini_3_accepts_temperature(self):
        for model_id in ("gemini-3.1-pro", "gemini-3.1-flash"):
            assert supports_temperature(model_id)

    def test_unknown_model_defaults_to_supporting_temperature(self):
        # Default safe assumption — caller should still resolve_model_id first.
        assert supports_temperature("nonexistent-model") is True


class TestListModels:
    def test_each_provider_lists_only_its_models(self):
        for provider in ("openai", "anthropic", "gemini"):
            for entry in list_models(provider):
                spec = get_model(entry["id"])
                assert spec is not None
                assert spec.provider == provider

    def test_unknown_provider_returns_empty_list(self):
        assert list_models("not-a-provider") == []


class TestPricing:
    def test_pricing_returns_zero_for_unknown_model(self):
        assert get_pricing("nope") == (0.0, 0.0)

    def test_pricing_returns_two_floats_for_known_model(self):
        rates = get_pricing("claude-sonnet-4-6")
        assert isinstance(rates, tuple) and len(rates) == 2
        assert all(isinstance(r, float) for r in rates)
