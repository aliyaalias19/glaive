"""Provider adapters: OpenAI-compatible and Anthropic wire formats."""
from __future__ import annotations

import json

import httpx

from glaive.llm.providers import AnthropicProvider, OpenAICompatProvider
from glaive.llm.types import Message, ToolCall, ToolSpec

TOOLS = [ToolSpec("lookup", "Look something up", {"type": "object",
                                                   "properties": {"q": {"type": "string"}}})]


def _client(handler) -> httpx.Client:  # noqa: ANN001
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_compat_wire_format_and_tool_calls() -> None:
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("authorization")
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={
            "model": "kimi-k3", "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            "choices": [{"finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "reasoning_content": "thinking...",
                "tool_calls": [{"id": "c1", "type": "function",
                                "function": {"name": "lookup", "arguments": '{"q": "x"}'}}]}}]})

    p = OpenAICompatProvider("kimi", "https://api.moonshot.ai/v1/", "kimi-k3", "sk-test",
                             client=_client(handler))
    r = p.complete([Message.system("s"), Message.user("u")], TOOLS)
    assert seen["url"] == "https://api.moonshot.ai/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-test"
    assert seen["body"]["tools"][0]["function"]["name"] == "lookup"
    call = r.message.tool_calls[0]
    assert (call.name, call.arguments) == ("lookup", {"q": "x"})
    assert r.usage.total == 18
    # Kimi/DeepSeek require reasoning_content to be echoed back on the next turn
    wire = OpenAICompatProvider.to_wire([r.message, Message.tool_result(call, "result")])
    assert wire[0]["reasoning_content"] == "thinking..."
    assert wire[0]["tool_calls"][0]["function"]["arguments"] == '{"q": "x"}'
    assert wire[1] == {"role": "tool", "tool_call_id": "c1", "content": "result"}


def test_invalid_tool_json_is_reported_not_raised() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "tool_calls": [
            {"id": "c", "function": {"name": "lookup", "arguments": "{broken"}}]}}]})

    r = OpenAICompatProvider("x", "http://h", "m", client=_client(handler)).complete([Message.user("u")])
    assert r.message.tool_calls[0].parse_error


def test_anthropic_wire_format() -> None:
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["headers"] = req.headers
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={
            "model": "claude-sonnet-5-5", "stop_reason": "tool_use",
            "usage": {"input_tokens": 5, "output_tokens": 3},
            "content": [{"type": "text", "text": "Let me check."},
                        {"type": "tool_use", "id": "tu1", "name": "lookup", "input": {"q": "y"}}]})

    p = AnthropicProvider("claude-sonnet-5-5", "key", client=_client(handler))
    call = ToolCall("tu0", "lookup", {"q": "a"})
    history = [Message.system("sys"), Message.user("u"),
               Message("assistant", None, tool_calls=[call]),
               Message.tool_result(call, "r1"), Message.tool_result(ToolCall("tu9", "lookup", {}), "r2")]
    r = p.complete(history, TOOLS)
    body = seen["body"]
    assert seen["headers"]["x-api-key"] == "key" and seen["headers"]["anthropic-version"]
    assert body["system"] == "sys"
    assert body["tools"][0]["input_schema"]["type"] == "object"
    # consecutive tool results are merged into one user message
    assert [b["tool_use_id"] for b in body["messages"][2]["content"]] == ["tu0", "tu9"]
    assert r.message.content == "Let me check." and r.message.tool_calls[0].id == "tu1"
    # replaying Claude's message sends its original content blocks back
    _, wire = AnthropicProvider.to_wire([r.message])
    assert wire[0]["content"][1]["type"] == "tool_use"
