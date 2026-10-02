"""The full investigation pipeline: triage, Hunter, Skeptic, Reporter, save."""
from __future__ import annotations

import json

from glaive.agents import Investigation
from glaive.llm import LLMError, Message, Router, ScriptedProvider
from glaive.mcp_server.session import GlaiveSession
from tests.v02.agent_scripts import fresh_hunter_script


def test_full_investigation_with_one_model(demo_session: GlaiveSession) -> None:
    hunter = fresh_hunter_script()

    def model(messages: list[Message], tools: object) -> Message:
        system = messages[0].content or ""
        if "GLAIVE Hunter" in system:
            return hunter(messages, tools)
        if "GLAIVE Skeptic" in system:
            return Message("assistant", json.dumps({"verdict": "upheld", "argument": "Supported.",
                                                    "alternative_explanation": None}))
        return Message("assistant", "## Overview\nThe workstation beaconed to its C2 server [F1].")

    result = Investigation(demo_session, Router([ScriptedProvider(model)]), skeptic=True).run()
    assert result.mode == "ai" and result.hunter.finished
    assert result.skeptic["upheld"] >= 1
    assert result.report.generated_by.startswith("scripted")
    reloaded = GlaiveSession.load(demo_session.analysis_dir)
    assert reloaded.summary_markdown and len(reloaded.report.findings) == result.findings_total
    actions = {e["action"] for e in reloaded.audit_log}
    assert {"investigation_started", "tool_call", "gate_decision", "investigation_finished"} <= actions


def test_model_outage_does_not_lose_offline_findings(demo_session: GlaiveSession) -> None:
    def down(messages: list[Message], tools: object) -> Message:
        raise LLMError("service unavailable", retryable=False)

    result = Investigation(demo_session, Router([ScriptedProvider(down)], sleep=lambda s: None)).run()
    assert result.triage_findings >= 10
    assert "model error" in result.hunter.stopped_reason
    assert result.report.generated_by.startswith("deterministic")
