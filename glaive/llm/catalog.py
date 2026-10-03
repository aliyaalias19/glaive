"""Provider catalog and environment-based configuration.

Set the key for any provider you have and GLAIVE finds it. Several keys
make a fallback chain (order below, or set GLAIVE_PROVIDERS explicitly).

    ANTHROPIC_API_KEY   Claude                 (Anthropic)
    OPENAI_API_KEY      GPT                    (OpenAI)
    DEEPSEEK_API_KEY    DeepSeek               (DeepSeek, China)
    DASHSCOPE_API_KEY   Qwen                   (Alibaba Cloud Model Studio)
    MOONSHOT_API_KEY    Kimi                   (Moonshot AI)
    ZHIPUAI_API_KEY     GLM                    (Zhipu / BigModel; Z.ai via GLM_BASE_URL)
    ARK_API_KEY         Doubao                 (ByteDance Volcengine Ark)
    GEMINI_API_KEY      Gemini                 (Google, OpenAI-compatible endpoint)
    OPENROUTER_API_KEY  any model on OpenRouter
    SILICONFLOW_API_KEY open models on SiliconFlow
    OLLAMA_MODEL        local model via Ollama (fully offline), e.g. qwen3:8b
    GLAIVE_BASE_URL     any other OpenAI-compatible server (vLLM, SGLang,
                        LMDeploy, llama.cpp); pair with GLAIVE_MODEL

Overrides:
    GLAIVE_PROVIDERS="deepseek,anthropic,ollama"   explicit order
    GLAIVE_MODEL=...                               model for the first provider
    <NAME>_MODEL / <NAME>_BASE_URL                 per-provider model / endpoint, where
                                                   NAME is the provider name: ANTHROPIC,
                                                   OPENAI, DEEPSEEK, QWEN, KIMI, GLM, DOUBAO,
                                                   GEMINI, OPENROUTER, SILICONFLOW, OLLAMA
    GLAIVE_TOKEN_BUDGET=200000                     stop after this many tokens
    GLAIVE_PRIVACY=pseudonymize|local-only|off     what cloud models may see
                                                   (see glaive.security.privacy)

Default model names were checked against provider documentation in
October 2026. Providers rename models often; override them if a default
stops working.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from glaive.llm.providers import AnthropicProvider, OpenAICompatProvider, Provider
from glaive.llm.router import Router
from glaive.security.privacy import Pseudonymizer, is_local_provider, privacy_mode


@dataclass(frozen=True)
class Preset:
    name: str
    label: str
    key_env: str | None
    base_url: str
    default_model: str
    protocol: str = "openai"  # or "anthropic"
    region: str = "global"


PRESETS: dict[str, Preset] = {p.name: p for p in [
    Preset("anthropic", "Claude (Anthropic)", "ANTHROPIC_API_KEY", "https://api.anthropic.com",
           "claude-sonnet-5-5", protocol="anthropic", region="US"),
    Preset("openai", "GPT (OpenAI)", "OPENAI_API_KEY", "https://api.openai.com/v1",
           "gpt-5.4-mini", region="US"),
    Preset("deepseek", "DeepSeek", "DEEPSEEK_API_KEY", "https://api.deepseek.com",
           "deepseek-flash", region="CN"),
    Preset("qwen", "Qwen (Alibaba Model Studio)", "DASHSCOPE_API_KEY",
           "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "qwen-plus", region="CN"),
    Preset("kimi", "Kimi (Moonshot AI)", "MOONSHOT_API_KEY", "https://api.moonshot.ai/v1",
           "kimi-k3", region="CN"),
    Preset("glm", "GLM (Zhipu / BigModel)", "ZHIPUAI_API_KEY",
           "https://open.bigmodel.cn/api/paas/v4", "glm-5.1", region="CN"),
    Preset("doubao", "Doubao (Volcengine Ark)", "ARK_API_KEY",
           "https://ark.cn-beijing.volces.com/api/v3", "doubao-seed-2-1-pro-260628", region="CN"),
    Preset("gemini", "Gemini (Google)", "GEMINI_API_KEY",
           "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-3.8-flash",
           region="US"),
    Preset("openrouter", "OpenRouter", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1",
           "anthropic/claude-sonnet-5.5"),
    Preset("siliconflow", "SiliconFlow", "SILICONFLOW_API_KEY", "https://api.siliconflow.cn/v1",
           "Qwen/Qwen3-32B", region="CN"),
    Preset("ollama", "Ollama (local, offline)", None, "http://localhost:11434/v1", "qwen3:8b",
           region="local"),
    Preset("custom", "Any OpenAI-compatible server", None, "", "", region="local"),
]}

AUTO_ORDER = ["anthropic", "openai", "deepseek", "qwen", "kimi", "glm", "doubao", "gemini",
              "openrouter", "siliconflow", "ollama", "custom"]


def _configured(preset: Preset, env: Mapping[str, str]) -> bool:
    if preset.name == "ollama":
        return bool(env.get("OLLAMA_MODEL") or env.get("OLLAMA_BASE_URL"))
    if preset.name == "custom":
        return bool(env.get("GLAIVE_BASE_URL"))
    return bool(preset.key_env and env.get(preset.key_env))


def build_provider(name: str, env: Mapping[str, str] | None = None, model: str | None = None,
                   client: httpx.Client | None = None) -> Provider:
    env = os.environ if env is None else env
    preset = PRESETS[name]
    up = name.upper()
    base = env.get(f"{up}_BASE_URL") or (env.get("GLAIVE_BASE_URL") if name == "custom" else None) \
        or preset.base_url
    model = model or env.get(f"{up}_MODEL") or (env.get("GLAIVE_MODEL") if name == "custom" else None) \
        or preset.default_model
    if not base or not model:
        raise ValueError(f"Provider {name!r} needs a base URL and a model name.")
    key = env.get(preset.key_env) if preset.key_env else env.get(f"{up}_API_KEY")
    if preset.protocol == "anthropic":
        if not key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        return AnthropicProvider(model=model, api_key=key, base_url=base, client=client)
    headers = {}
    if name == "openrouter":
        headers = {"HTTP-Referer": "https://github.com/aliyaalias19/glaive", "X-Title": "GLAIVE"}
    return OpenAICompatProvider(name=name, base_url=base, model=model, api_key=key,
                                client=client, extra_headers=headers)


def detect_providers(env: Mapping[str, str] | None = None) -> list[str]:
    """Names of providers that have credentials/config in the environment."""
    env = os.environ if env is None else env
    explicit = [p.strip() for p in (env.get("GLAIVE_PROVIDERS") or "").split(",") if p.strip()]
    if explicit:
        unknown = [p for p in explicit if p not in PRESETS]
        if unknown:
            raise ValueError(f"Unknown provider(s) in GLAIVE_PROVIDERS: {unknown}. "
                             f"Choose from {sorted(PRESETS)}.")
        return explicit
    return [n for n in AUTO_ORDER if _configured(PRESETS[n], env)]


def router_from_env(env: Mapping[str, str] | None = None, client: httpx.Client | None = None,
                    **router_kwargs: object) -> Router | None:
    """Build a Router from environment variables; None if no model is configured."""
    env = os.environ if env is None else env
    names = detect_providers(env)
    if not names:
        return None
    mode = privacy_mode(env)
    providers = []
    for i, n in enumerate(names):
        model = env.get("GLAIVE_MODEL") if i == 0 and env.get("GLAIVE_MODEL") else None
        providers.append(build_provider(n, env, model=model, client=client))
    if mode == "local-only":
        providers = [p for p in providers if is_local_provider(p)]
        if not providers:
            return None
    budget = env.get("GLAIVE_TOKEN_BUDGET")
    if budget and "token_budget" not in router_kwargs:
        router_kwargs["token_budget"] = int(budget)
    if mode == "pseudonymize" and "privacy" not in router_kwargs:
        router_kwargs["privacy"] = Pseudonymizer()
    return Router(providers, **router_kwargs)  # type: ignore[arg-type]
