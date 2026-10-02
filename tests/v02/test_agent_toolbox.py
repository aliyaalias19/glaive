"""The tools agents may call: validation, read-only mode, spotlighted results."""
from __future__ import annotations

from glaive.agents.toolbox import AgentToolbox
from glaive.llm.types import ToolCall
from glaive.mcp_server.session import GlaiveSession


def test_toolbox_validates_and_spotlights(demo_session: GlaiveSession) -> None:
    tb = AgentToolbox(demo_session)
    bad = tb.execute(ToolCall("1", "list_alerts", {"min_level": "extreme"}))
    assert "bad_arguments" in bad and bad.startswith("<tool_result-")
    assert "unknown_tool" in tb.execute(ToolCall("2", "rm_rf", {}))
    assert "bad_arguments" in tb.execute(ToolCall("3", "x", {}, parse_error="invalid JSON"))
    names = {s.name for s in tb.specs()}
    assert {"commit_finding", "finish", "neighbors", "timeline"} <= names
    assert "commit_finding" not in {s.name for s in AgentToolbox(demo_session, readonly=True).specs()}


def test_planted_injection_reaches_the_agent_only_as_data(demo_session: GlaiveSession) -> None:
    out = AgentToolbox(demo_session).execute(
        ToolCall("1", "list_alerts", {"rule_contains": "prompt-injection", "min_level": "low"}))
    assert "Ignore previous instructions" in out
    tag = out.splitlines()[0]
    assert tag.startswith("<tool_result-") and out.rstrip().endswith(tag.replace("<", "</"))
