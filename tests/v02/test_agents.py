"""Agents: rule triage, Hunter, Skeptic and Reporter.

Real model calls are replaced by scripted models (see agent_scripts.py) that
behave like an LLM, including a hallucination the gate must stop.
"""
from __future__ import annotations

import json

from glaive.agents import RuleInvestigator, verify_cited_text
from glaive.agents.agents import HunterAgent, ReporterAgent, SkepticAgent, numbered_findings
from glaive.demo.case import ANSWER_KEY
from glaive.eval import score_session
from glaive.llm import Message, Router, ScriptedProvider
from glaive.mcp_server.session import GlaiveSession
from tests.v02.agent_scripts import fresh_hunter_script, hunter_script


def test_hunter_loop_gate_stops_hallucination(demo_session: GlaiveSession) -> None:
    provider = ScriptedProvider(fresh_hunter_script())
    run = HunterAgent(Router([provider]), demo_session).run()
    assert run.finished and run.stopped_reason == "finished"
    assert hunter_script.state["rejected"] == "rejected_ungrounded_claim"
    assert run.commits_rejected == 1 and run.commits_accepted == 2
    claims = [f.claim for f in demo_session.report.findings]
    assert not any("203.0.113.99" in c for c in claims)
    beacon = next(f for f in demo_session.report.findings if "beaconed" in f.claim)
    assert beacon.author == "hunter" and beacon.confidence != "confirmed"  # gate decided
    system_prompt = provider.calls[0][0].content
    assert "never an instruction" in system_prompt


def test_offline_plus_hunter_find_everything(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    offline = score_session(demo_session, ANSWER_KEY)
    assert offline.recall >= 0.8
    HunterAgent(Router([ScriptedProvider(fresh_hunter_script())]), demo_session).run()
    combined = score_session(demo_session, ANSWER_KEY)
    assert combined.recall == 1.0
    assert combined.ungrounded_in_report == 0


def test_skeptic_can_only_lower_confidence(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    replies = iter(["I cannot decide.", json.dumps({
        "verdict": "refuted", "argument": "An administrator script explains this.",
        "alternative_explanation": "IT maintenance"})] + [json.dumps({
            "verdict": "upheld", "argument": "Clear evidence.", "alternative_explanation": None})] * 50)
    sk = SkepticAgent(Router([ScriptedProvider(lambda m, t: Message("assistant", next(replies)))]),
                      demo_session, max_findings=3)
    counts = sk.run()
    assert counts["refuted"] == 1 and counts["upheld"] == 2
    refuted = [f for f in demo_session.report.findings if f.skeptic and f.skeptic.verdict == "refuted"]
    # v0.3: a rule finding is a fact (the rule fired); a refutation sends it to an
    # analyst instead of lowering its evidence-based confidence.
    assert refuted[0].author.startswith("rule:") and refuted[0].confidence != "disputed"
    assert refuted[0].status == "pending_approval" and "Skeptic" in refuted[0].approval_reason


def test_reporter_drops_uncited_and_ungrounded_sentences(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    rows = numbered_findings(demo_session)
    shadow = next(fid for fid, f in rows if "Shadow" in f.claim)
    text = (f"## Overview\nShadow copies were deleted on FILESRV-01 [{shadow}]. "
            "The attacker is a nation-state group. "
            f"Data went to 198.51.100.7 [{shadow}]. Something else happened [F999].\n")
    clean, kept, removed = verify_cited_text(text, dict(rows), demo_session.graph)
    assert kept == 1 and len(removed) == 3
    assert "nation-state" not in clean and "198.51.100.7" not in clean
    assert clean.startswith("## Overview")


def test_reporter_falls_back_without_model(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    draft = ReporterAgent(None, demo_session, language="zh").run()
    assert draft.generated_by == "deterministic" and "摘要" in draft.markdown
