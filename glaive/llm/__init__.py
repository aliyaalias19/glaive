"""Model-agnostic LLM layer: provider adapters, router, environment config."""
from glaive.llm.catalog import PRESETS, build_provider, detect_providers, router_from_env
from glaive.llm.providers import (
    AnthropicProvider,
    OpenAICompatProvider,
    Provider,
    ScriptedProvider,
)
from glaive.llm.router import Router
from glaive.llm.types import (
    BudgetExceeded,
    LLMError,
    LLMResponse,
    Message,
    ToolCall,
    ToolSpec,
    Usage,
)

__all__ = [
    "PRESETS", "AnthropicProvider", "BudgetExceeded", "LLMError", "LLMResponse", "Message",
    "OpenAICompatProvider", "Provider", "Router", "ScriptedProvider", "ToolCall", "ToolSpec",
    "Usage", "build_provider", "detect_providers", "router_from_env",
]
