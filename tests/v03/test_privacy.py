"""Pseudonymisation of case data sent to cloud models."""
from __future__ import annotations

import json

import httpx
import pytest

from glaive.demo.case import ALICE_SID, C2, FS, WS
from glaive.llm import Message, OpenAICompatProvider, Router, ScriptedProvider, ToolCall
from glaive.llm.catalog import router_from_env
from glaive.mcp_server.session import GlaiveSession
from glaive.security.privacy import (
    Pseudonymizer,
    is_local_provider,
    is_local_url,
    privacy_mode,
)


def test_round_trip_and_stable_tokens() -> None:
    p = Pseudonymizer()
    t1 = p.add("host", "WS-FIN-07.corp.example")
    p.alias("WS-FIN-07", t1 or "")
    assert t1 == "HOST_1" and p.add("host", "ws-fin-07.CORP.example") == "HOST_1"
    p.add("user", "alice")
    text = "alice logged on to WS-FIN-07.corp.example; WS-FIN-07_Security.evtx; WS-FIN-070"
    masked = p.mask(text)
    assert masked == "USER_1 logged on to HOST_1; HOST_1_Security.evtx; WS-FIN-070"
    assert p.unmask(masked) == "alice logged on to WS-FIN-07.corp.example; " \
                               "WS-FIN-07.corp.example_Security.evtx; WS-FIN-070"
    assert p.unmask("user_1 and HOST_10 and Host_1.") == "alice and HOST_10 and " \
                                                          "WS-FIN-07.corp.example."


def test_what_is_masked_and_what_is_kept() -> None:
    p = Pseudonymizer()
    p.learn_text(r'{"user": "CORP\\it.bob", "path": "C:\\Users\\alice\\AppData\\x.exe", '
                 r'"src": "10.20.4.17", "dst": "203.0.113.47", "mail": "j.doe@corp.example", '
                 f'"sid": "{ALICE_SID}", "sys": "S-1-5-18", "acct": "NT AUTHORITY\\\\SYSTEM", '
                 r'"reg": "HKLM\\SOFTWARE\\Run", "ver": "10.0.18362.1"}')
    s = p.summary()
    assert s == {"domain": 1, "email": 1, "ip": 1, "sid": 1, "user": 2}, s
    out = p.mask(r'C:\\Users\\alice\\x.exe from 10.20.4.17 to 203.0.113.47 via HKLM\\SOFTWARE')
    assert out == r"C:\\Users\\USER_1\\x.exe from IP_1 to 203.0.113.47 via HKLM\\SOFTWARE"
    assert p.add("user", "SYSTEM") is None and p.add("ip", "8.8.8.8") is None
    assert p.add("sid", "S-1-5-18") is None


def test_learn_graph_masks_the_demo_case(demo_session: GlaiveSession) -> None:
    p = Pseudonymizer()
    p.learn_graph(demo_session.graph)
    text = f"{WS} {FS} WS-FIN-07 alice it.bob {ALICE_SID} {C2}"
    masked = p.mask(text) or ""
    for real in (WS, FS, "WS-FIN-07", "alice", "it.bob", ALICE_SID, "corp.example"):
        assert real.lower() not in masked.lower(), real
    assert C2 in masked  # the attacker's public address is kept for the model
    assert p.unmask(masked) == text.replace("WS-FIN-07 ", f"{WS} ", 1)


def test_local_and_cloud_endpoints() -> None:
    assert is_local_url("http://localhost:11434/v1") and is_local_url("http://10.1.2.3:8000/v1")
    assert is_local_url("http://gpu-box.local:8000") and not is_local_url("https://api.deepseek.com")
    assert is_local_url("http://gpu-box:8000/v1") and not is_local_url(None)
    assert is_local_provider(OpenAICompatProvider("ollama", "http://x.example", "m"))
    assert not is_local_provider(OpenAICompatProvider("deepseek", "https://api.deepseek.com", "m"))


def test_privacy_mode_env() -> None:
    assert privacy_mode({}) == "pseudonymize"
    assert privacy_mode({"GLAIVE_PRIVACY": "LOCAL-ONLY"}) == "local-only"
    with pytest.raises(ValueError):
        privacy_mode({"GLAIVE_PRIVACY": "maybe"})


def test_router_masks_cloud_calls_and_restores_replies() -> None:
    p = Pseudonymizer()
    p.add("host", WS)
    p.add("user", "alice")
    seen: list[list[Message]] = []

    def model(messages, tools):  # noqa: ANN001, ANN202
        seen.append(messages)
        return Message("assistant", "HOST_1 is compromised by USER_1.", tool_calls=[
            ToolCall("c1", "query_graph", {"filters": [{"field": "hostname", "value": "HOST_1"}]},
                     raw_arguments='{"filters": [{"field": "hostname", "value": "HOST_1"}]}')])

    router = Router([ScriptedProvider(model, name="deepseek")], privacy=p)
    history = [Message.system("You are GLAIVE. Keep alice's words."),
               Message.user(f"What happened on {WS}? alice says hi")]
    resp = router.complete(history, None)
    sent = seen[0]
    assert sent[0].content == history[0].content  # system prompt is GLAIVE's own text
    assert WS not in (sent[1].content or "") and "alice" not in (sent[1].content or "")
    assert history[1].content and WS in history[1].content  # history stays real
    assert resp.message.content == f"{WS} is compromised by alice."
    call = resp.message.tool_calls[0]
    assert call.arguments["filters"][0]["value"] == WS
    assert json.loads(call.raw_arguments)["filters"][0]["value"] == WS
    assert router.summary()["privacy"]["pseudonymized"] == {"host": 1, "user": 1}


def test_local_models_get_real_data() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    p = Pseudonymizer()
    p.add("host", WS)
    local = OpenAICompatProvider("custom", "http://127.0.0.1:8000/v1", "qwen3", client=client)
    Router([local], privacy=p).complete([Message.user(f"look at {WS}")], None)
    assert WS in bodies[0]["messages"][0]["content"]


def test_router_from_env_privacy_modes() -> None:
    env = {"DEEPSEEK_API_KEY": "k", "OLLAMA_MODEL": "qwen3:8b"}
    r = router_from_env(env)
    assert r is not None and r.privacy is not None and len(r.providers) == 2
    r = router_from_env({**env, "GLAIVE_PRIVACY": "off"})
    assert r is not None and r.privacy is None
    r = router_from_env({**env, "GLAIVE_PRIVACY": "local-only"})
    assert r is not None and [p.name for p in r.providers] == ["ollama"]
    assert router_from_env({"DEEPSEEK_API_KEY": "k", "GLAIVE_PRIVACY": "local-only"}) is None


def test_investigation_never_shows_real_names_to_a_cloud_model(
        demo_session: GlaiveSession) -> None:
    """A whole investigation: the cloud model only ever sees tokens, and a
    finding it writes with tokens is checked by the gate with real values."""
    from glaive.agents import Investigation

    seen: list[str] = []

    def model(messages, tools):  # noqa: ANN001, ANN202
        seen.extend(m.content or "" for m in messages if m.role != "system")
        turns = sum(1 for m in messages if m.role == "assistant")
        if tools is None:  # skeptic verdict / reporter
            return Message("assistant", '{"verdict": "upheld", "argument": "fine", '
                                        '"alternative_explanation": null}')
        if turns == 0:
            return Message("assistant", None, tool_calls=[ToolCall(
                "a", "query_graph", {"node_type": "Process", "filters": [
                    {"field": "command_line", "op": "icontains", "value": "vssadmin"}]})])
        if turns == 1:
            payload = json.loads("\n".join((messages[-1].content or "").splitlines()[1:-1]))
            key = payload["nodes"][0]["canonical_key"]
            assert "HOST_" in json.dumps(key)  # the model sees the token
            return Message("assistant", None, tool_calls=[ToolCall("b", "commit_finding", {
                "claim": "vssadmin.exe deleted all shadow copies on HOST_2.",
                "supporting_node_keys": [key], "severity": "critical",
                "mitre_techniques": ["T1490"]})])
        return Message("assistant", None, tool_calls=[ToolCall("c", "finish", {
            "summary": "Shadow copies were deleted on HOST_2."})])

    p = Pseudonymizer()
    router = Router([ScriptedProvider(model, name="openai")], privacy=p)
    Investigation(demo_session, router, max_steps=5, skeptic=False).run()
    everything = "\n".join(seen).lower()
    for real in (WS.lower(), FS.lower(), "ws-fin-07", "filesrv-01", "corp.example", "alice",
                 ALICE_SID.lower()):
        assert real not in everything, real
    hunter = [f for f in demo_session.report.findings if f.author == "hunter"]
    assert hunter and FS in hunter[0].claim  # restored before the gate checked it
