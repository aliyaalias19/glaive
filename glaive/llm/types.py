"""Provider-neutral message and tool-call types.

Every provider adapter converts to and from these, so agents never see a
vendor's wire format and any model can be swapped for any other.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class ToolSpec:
    """A function the model may call. `parameters` is a JSON Schema object."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""
    parse_error: str | None = None  # set when the model sent invalid JSON


@dataclass
class Message:
    role: Role
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None
    # Provider-specific fields that must be echoed back unchanged on the next
    # turn (e.g. Kimi/DeepSeek `reasoning_content`, Anthropic content blocks).
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def system(cls, text: str) -> Message:
        return cls("system", text)

    @classmethod
    def user(cls, text: str) -> Message:
        return cls("user", text)

    @classmethod
    def tool_result(cls, call: ToolCall, content: str) -> Message:
        return cls("tool", content, tool_call_id=call.id, name=call.name)


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class LLMResponse:
    message: Message
    usage: Usage
    provider: str
    model: str
    latency_ms: float
    finish_reason: str | None = None


class LLMError(Exception):
    """A model call failed. `retryable` errors (rate limits, timeouts, 5xx)
    are retried; others move straight to the next provider."""

    def __init__(self, message: str, *, retryable: bool = False, status: int | None = None,
                 provider: str | None = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.provider = provider


class BudgetExceeded(LLMError):
    """The investigation's token budget is used up."""
