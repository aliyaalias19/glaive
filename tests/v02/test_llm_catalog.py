"""Provider presets and configuration from environment variables."""
from __future__ import annotations

import pytest

from glaive.llm.catalog import PRESETS, build_provider, detect_providers, router_from_env


def test_environment_detection_and_overrides() -> None:
    env = {"DEEPSEEK_API_KEY": "d", "ANTHROPIC_API_KEY": "a", "OLLAMA_MODEL": "qwen3:8b",
           "GLAIVE_MODEL": "claude-opus-5-5", "DEEPSEEK_MODEL": "deepseek-v4-pro"}
    assert detect_providers(env) == ["anthropic", "deepseek", "ollama"]
    r = router_from_env(env)
    assert r.describe() == ("anthropic:claude-opus-5-5 -> deepseek:deepseek-v4-pro -> "
                            "ollama:qwen3:8b")
    assert detect_providers({"GLAIVE_PROVIDERS": "ollama", "OLLAMA_MODEL": "x"}) == ["ollama"]
    with pytest.raises(ValueError):
        detect_providers({"GLAIVE_PROVIDERS": "nope"})
    assert router_from_env({}) is None
    p = build_provider("qwen", {"DASHSCOPE_API_KEY": "k",
                                "QWEN_BASE_URL": "https://ws1.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"})
    assert p.base_url.startswith("https://ws1.cn-beijing")
    custom = build_provider("custom", {"GLAIVE_BASE_URL": "http://gpu:8000/v1", "GLAIVE_MODEL": "qwen3"})
    assert (custom.base_url, custom.model) == ("http://gpu:8000/v1", "qwen3")
    assert router_from_env({"OLLAMA_MODEL": "x", "GLAIVE_TOKEN_BUDGET": "500"}).token_budget == 500


@pytest.mark.parametrize("name", ["anthropic", "openai", "deepseek", "qwen", "kimi", "glm",
                                  "doubao", "gemini", "openrouter", "siliconflow"])
def test_every_hosted_preset_builds_from_its_key(name: str) -> None:
    preset = PRESETS[name]
    p = build_provider(name, {preset.key_env: "k"})
    assert p.model == preset.default_model and p.base_url.startswith("https://")
    assert detect_providers({preset.key_env: "k"}) == [name]
