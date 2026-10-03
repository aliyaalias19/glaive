"""Audit trail: spans for investigations, agents, model and tool calls."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaive import observability as obs
from glaive.demo.case import WS
from glaive.llm import Message, Router, ScriptedProvider, ToolCall
from glaive.mcp_server.session import GlaiveSession


def test_spans_nest_and_are_written(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    with obs.tracing(path) as tracer:
        with obs.span("outer", a=1) as outer:
            with obs.span("inner") as inner:
                inner.set("b", [1, 2])
                inner.set("skipped", None)
            with pytest.raises(ValueError), obs.span("broken"):
                raise ValueError("boom")
        assert outer.parent_id is None
    rows = obs.read_trace(path)
    assert [r["name"] for r in rows] == ["inner", "broken", "outer"]
    by = {r["name"]: r for r in rows}
    assert by["inner"]["parent_id"] == by["outer"]["span_id"] == by["broken"]["parent_id"]
    assert {r["trace_id"] for r in rows} == {tracer.trace_id}
    assert by["inner"]["attributes"] == {"b": [1, 2]} and by["outer"]["attributes"] == {"a": 1}
    assert by["broken"]["status"] == "error" and by["broken"]["error"] == "boom"
    assert by["outer"]["duration_ms"] >= 0


def test_span_without_a_tracer_is_harmless() -> None:
    with obs.span("lonely", x=1) as s:
        s.set("y", 2)
    assert s.attributes == {"x": 1, "y": 2} and obs.current_tracer() is None


def test_unreadable_lines_are_skipped(tmp_path: Path) -> None:
    p = tmp_path / "t.jsonl"
    p.write_text('{"name": "ok"}\nnot json\n', encoding="utf-8")
    assert obs.read_trace(p) == [{"name": "ok"}] and obs.read_trace(tmp_path / "none") == []


def _scripted() -> Router:
    def model(messages, tools):  # noqa: ANN001, ANN202
        turns = sum(1 for m in messages if m.role == "assistant")
        if tools is None:
            return Message("assistant", "Shadow copies were deleted [F1].")
        if turns == 0:
            return Message("assistant", None, tool_calls=[ToolCall(
                "a", "query_graph", {"node_type": "Process", "filters": [
                    {"field": "command_line", "op": "icontains", "value": "vssadmin"}]})])
        if turns == 1:
            key = json.loads("\n".join((messages[-1].content or "").splitlines()[1:-1]))[
                "nodes"][0]["canonical_key"]
            return Message("assistant", None, tool_calls=[ToolCall("b", "commit_finding", {
                "claim": "vssadmin.exe deleted all shadow copies.",
                "supporting_node_keys": [key], "severity": "critical"})])
        return Message("assistant", None, tool_calls=[ToolCall("c", "finish", {
            "summary": "Shadow copies deleted."})])
    return Router([ScriptedProvider(model, name="deepseek", model="deepseek-flash")])


def test_investigation_writes_an_audit_trail(demo_session: GlaiveSession) -> None:
    from glaive.agents import Investigation

    Investigation(demo_session, _scripted(), max_steps=4, skeptic=False).run()
    path = demo_session.analysis_dir / "trace.jsonl"
    spans = obs.read_trace(path)
    names = [s["name"] for s in spans]
    assert names[-1] == "investigation" and "invoke_agent hunter" in names
    assert "invoke_agent rules" in names and "invoke_agent reporter" in names
    root = spans[-1]
    assert root["parent_id"] is None and root["attributes"]["glaive.mode"] == "ai"
    chats = [s for s in spans if s["attributes"].get("gen_ai.operation.name") == "chat"]
    assert chats and all(s["attributes"]["gen_ai.provider.name"] == "deepseek" for s in chats)
    assert all(s["attributes"]["gen_ai.usage.input_tokens"] > 0 for s in chats)
    commit = next(s for s in spans if s["name"] == "execute_tool commit_finding")
    assert commit["attributes"]["glaive.gate.decision"].startswith(("accepted", "downgraded"))
    hunter = next(s for s in spans if s["name"] == "invoke_agent hunter")
    assert commit["parent_id"] == hunter["span_id"]
    # Case data is not copied into the trace: no prompts, no answers, no host names.
    text = path.read_text(encoding="utf-8")
    assert WS not in text and "vssadmin" not in text
    s = obs.summarize(spans)
    assert s["models"]["deepseek:deepseek-flash"]["calls"] == len(chats)
    assert s["tools"]["commit_finding"] == 1 and s["investigations"] == 1


def test_failed_provider_is_an_error_span(tmp_path: Path) -> None:
    from glaive.llm.types import LLMError

    def broken(messages, tools):  # noqa: ANN001, ANN202
        raise LLMError("bad key", retryable=False)

    def fine(messages, tools):  # noqa: ANN001, ANN202
        return Message("assistant", "hi")

    router = Router([ScriptedProvider(broken, name="openai"), ScriptedProvider(fine, name="kimi")])
    with obs.tracing(tmp_path / "t.jsonl"):
        router.complete([Message.user("x")])
    spans = obs.read_trace(tmp_path / "t.jsonl")
    assert [(s["attributes"]["gen_ai.provider.name"], s["status"]) for s in spans] == [
        ("openai", "error"), ("kimi", "ok")]


def test_cli_trace(demo_session: GlaiveSession) -> None:
    from typer.testing import CliRunner

    from glaive.agents import Investigation
    from glaive.cli import app

    Investigation(demo_session, _scripted(), max_steps=4, skeptic=False).run()
    r = CliRunner().invoke(app, ["trace", str(demo_session.analysis_dir)])
    assert r.exit_code == 0, r.output
    assert "deepseek:deepseek-flash" in r.output and "commit_finding" in r.output
    r = CliRunner().invoke(app, ["trace", str(demo_session.analysis_dir), "--json"])
    assert json.loads(r.output)["investigations"] == 1
    assert CliRunner().invoke(app, ["trace", str(demo_session.analysis_dir / "x")]).exit_code == 1


def test_spans_are_mirrored_to_opentelemetry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    monkeypatch.setitem(obs._OTEL_STATE, "tracer", provider.get_tracer("glaive-test"))
    with obs.tracing(tmp_path / "t.jsonl"), obs.span("chat m", **{
            "gen_ai.operation.name": "chat", "glaive.list": ["a"]}):
        with obs.span("execute_tool x"):
            pass
    done = {s.name: s for s in exporter.get_finished_spans()}
    assert set(done) == {"chat m", "execute_tool x"}
    assert done["chat m"].attributes["gen_ai.operation.name"] == "chat"
    assert done["chat m"].attributes["glaive.list"] == '["a"]'
    assert done["execute_tool x"].parent.span_id == done["chat m"].context.span_id
