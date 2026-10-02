"""Model provider adapters.

Two wire protocols cover nearly every model in 2026:
  - OpenAI Chat Completions: OpenAI, DeepSeek, Qwen (DashScope), Kimi
    (Moonshot), GLM (Zhipu / Z.ai), Doubao (Volcengine Ark), Gemini's
    OpenAI-compatible endpoint, OpenRouter, SiliconFlow, and local servers
    (Ollama, vLLM, SGLang, LMDeploy, llama.cpp).
  - Anthropic Messages: Claude.

Plus ScriptedProvider for tests and demos. Only httpx is required.
"""
from __future__ import annotations

import json
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

import httpx

from glaive.llm.types import LLMError, LLMResponse, Message, ToolCall, ToolSpec, Usage

DEFAULT_TIMEOUT = httpx.Timeout(120.0, connect=15.0)


def _raise_for_status(resp: httpx.Response, provider: str) -> None:
    if resp.status_code < 400:
        return
    retryable = resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500
    try:
        detail = resp.json()
    except ValueError:
        detail = resp.text[:300]
    raise LLMError(f"{provider} HTTP {resp.status_code}: {str(detail)[:300]}",
                   retryable=retryable, status=resp.status_code, provider=provider)


def _parse_args(raw: Any) -> tuple[dict[str, Any], str, str | None]:
    if isinstance(raw, dict):
        return raw, json.dumps(raw), None
    text = raw or "{}"
    try:
        val = json.loads(text)
        if not isinstance(val, dict):
            return {}, text, "arguments must be a JSON object"
        return val, text, None
    except json.JSONDecodeError as e:
        return {}, text, f"invalid JSON arguments: {e}"


class Provider(ABC):
    """One model endpoint."""

    name: str
    model: str

    @abstractmethod
    def complete(self, messages: list[Message], tools: list[ToolSpec] | None = None, *,
                 temperature: float = 0.0, max_tokens: int = 2048,
                 json_mode: bool = False) -> LLMResponse:
        ...


class OpenAICompatProvider(Provider):
    """Any server that speaks the OpenAI Chat Completions protocol."""

    def __init__(self, name: str, base_url: str, model: str, api_key: str | None = None,
                 client: httpx.Client | None = None, extra_headers: dict[str, str] | None = None,
                 extra_body: dict[str, Any] | None = None) -> None:
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self.extra_headers = extra_headers or {}
        self.extra_body = extra_body or {}

    @staticmethod
    def to_wire(messages: list[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "tool":
                out.append({"role": "tool", "tool_call_id": m.tool_call_id,
                            "content": m.content or ""})
                continue
            d: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_calls:
                d["tool_calls"] = [{"id": c.id, "type": "function",
                                    "function": {"name": c.name,
                                                 "arguments": c.raw_arguments or json.dumps(c.arguments)}}
                                   for c in m.tool_calls]
            for k, v in m.extra.items():  # e.g. reasoning_content (Kimi, DeepSeek)
                if not k.startswith("anthropic_"):
                    d[k] = v
            if d["content"] is None and m.role != "assistant":
                d["content"] = ""
            out.append(d)
        return out

    def complete(self, messages: list[Message], tools: list[ToolSpec] | None = None, *,
                 temperature: float = 0.0, max_tokens: int = 2048,
                 json_mode: bool = False) -> LLMResponse:
        body: dict[str, Any] = {"model": self.model, "messages": self.to_wire(messages),
                                "temperature": temperature, "max_tokens": max_tokens,
                                **self.extra_body}
        if tools:
            body["tools"] = [{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters}}
                for t in tools]
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        start = time.perf_counter()
        try:
            resp = self.client.post(f"{self.base_url}/chat/completions", json=body,
                                    headers=headers)
        except httpx.TimeoutException as e:
            raise LLMError(f"{self.name} timed out: {e}", retryable=True,
                           provider=self.name) from e
        except httpx.TransportError as e:
            raise LLMError(f"{self.name} connection failed: {e}", retryable=True,
                           provider=self.name) from e
        latency = (time.perf_counter() - start) * 1000
        _raise_for_status(resp, self.name)
        try:
            data = resp.json()
            choice = data["choices"][0]
            msg = choice["message"]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            raise LLMError(f"{self.name} returned an unexpected body: {resp.text[:200]}",
                           retryable=True, provider=self.name) from e
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            args, raw, err = _parse_args(fn.get("arguments"))
            calls.append(ToolCall(id=tc.get("id") or f"call_{uuid.uuid4().hex[:8]}",
                                  name=fn.get("name", ""), arguments=args, raw_arguments=raw,
                                  parse_error=err))
        extra = {k: msg[k] for k in ("reasoning_content",) if msg.get(k)}
        usage = data.get("usage") or {}
        return LLMResponse(
            message=Message("assistant", msg.get("content"), tool_calls=calls, extra=extra),
            usage=Usage(int(usage.get("prompt_tokens") or 0),
                        int(usage.get("completion_tokens") or 0)),
            provider=self.name, model=data.get("model") or self.model, latency_ms=latency,
            finish_reason=choice.get("finish_reason"))


class AnthropicProvider(Provider):
    """Claude via the Anthropic Messages API."""

    API_VERSION = "2023-06-01"

    def __init__(self, model: str, api_key: str, base_url: str = "https://api.anthropic.com",
                 client: httpx.Client | None = None, name: str = "anthropic") -> None:
        self.name = name
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)

    @staticmethod
    def to_wire(messages: list[Message]) -> tuple[str, list[dict[str, Any]]]:
        system = "\n\n".join(m.content or "" for m in messages if m.role == "system")
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "system":
                continue
            if m.role == "tool":
                block = {"type": "tool_result", "tool_use_id": m.tool_call_id,
                         "content": m.content or ""}
                # Consecutive tool results go in ONE user message.
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) \
                        and out[-1]["content"] and out[-1]["content"][0].get("type") == "tool_result":
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
                continue
            if m.role == "assistant":
                if "anthropic_content" in m.extra:  # replay exactly what Claude sent
                    out.append({"role": "assistant", "content": m.extra["anthropic_content"]})
                    continue
                blocks: list[dict[str, Any]] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for c in m.tool_calls:
                    blocks.append({"type": "tool_use", "id": c.id, "name": c.name,
                                   "input": c.arguments})
                out.append({"role": "assistant", "content": blocks or ""})
                continue
            out.append({"role": "user", "content": m.content or ""})
        return system, out

    def complete(self, messages: list[Message], tools: list[ToolSpec] | None = None, *,
                 temperature: float = 0.0, max_tokens: int = 2048,
                 json_mode: bool = False) -> LLMResponse:
        system, wire = self.to_wire(messages)
        body: dict[str, Any] = {"model": self.model, "max_tokens": max_tokens,
                                "temperature": temperature, "messages": wire}
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [{"name": t.name, "description": t.description,
                              "input_schema": t.parameters} for t in tools]
        headers = {"x-api-key": self.api_key, "anthropic-version": self.API_VERSION,
                   "content-type": "application/json"}
        start = time.perf_counter()
        try:
            resp = self.client.post(f"{self.base_url}/v1/messages", json=body, headers=headers)
        except httpx.TimeoutException as e:
            raise LLMError(f"{self.name} timed out: {e}", retryable=True,
                           provider=self.name) from e
        except httpx.TransportError as e:
            raise LLMError(f"{self.name} connection failed: {e}", retryable=True,
                           provider=self.name) from e
        latency = (time.perf_counter() - start) * 1000
        _raise_for_status(resp, self.name)
        try:
            data = resp.json()
            blocks = data["content"]
        except (ValueError, KeyError) as e:
            raise LLMError(f"{self.name} returned an unexpected body", retryable=True,
                           provider=self.name) from e
        texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
        calls = [ToolCall(id=b["id"], name=b["name"], arguments=b.get("input") or {},
                          raw_arguments=json.dumps(b.get("input") or {}))
                 for b in blocks if b.get("type") == "tool_use"]
        usage = data.get("usage") or {}
        return LLMResponse(
            message=Message("assistant", "\n".join(texts) or None, tool_calls=calls,
                            extra={"anthropic_content": blocks}),
            usage=Usage(int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)),
            provider=self.name, model=data.get("model") or self.model, latency_ms=latency,
            finish_reason=data.get("stop_reason"))


Script = Callable[[list[Message], list[ToolSpec] | None], Message]


class ScriptedProvider(Provider):
    """Deterministic provider for tests and demos: replays canned replies, or
    calls a function that decides the reply from the conversation."""

    def __init__(self, replies: list[Message] | Script, name: str = "scripted",
                 model: str = "scripted-1") -> None:
        self.name = name
        self.model = model
        self._replies = replies
        self.calls: list[list[Message]] = []

    def complete(self, messages: list[Message], tools: list[ToolSpec] | None = None, *,
                 temperature: float = 0.0, max_tokens: int = 2048,
                 json_mode: bool = False) -> LLMResponse:
        self.calls.append(list(messages))
        if callable(self._replies):
            msg = self._replies(messages, tools)
        else:
            if not self._replies:
                raise LLMError("scripted provider has no replies left", provider=self.name)
            msg = self._replies.pop(0)
        words = sum(len((m.content or "").split()) for m in messages)
        return LLMResponse(message=msg, usage=Usage(words, len((msg.content or "").split())),
                           provider=self.name, model=self.model, latency_ms=0.0,
                           finish_reason="tool_calls" if msg.tool_calls else "stop")
