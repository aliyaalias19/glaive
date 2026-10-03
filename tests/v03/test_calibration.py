"""Confidence calibration: is 'confirmed' right more often than 'inferred'?"""
from __future__ import annotations

from glaive.agents import RuleInvestigator
from glaive.demo.case import ANSWER_KEY
from glaive.eval import score_session
from glaive.mcp_server.session import GlaiveSession


def test_calibration_counts_findings_per_confidence(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    r = score_session(demo_session, ANSWER_KEY)
    cal = r.calibration
    assert sum(v["findings"] for v in cal.values()) == r.findings
    assert sum(v["matching"] for v in cal.values()) == r.findings_matching
    d = r.to_dict()["calibration"]
    assert d and all(0.0 <= v["share"] <= 1.0 for v in d.values())
    assert "| Confidence | Findings | Match the key |" in r.to_markdown()


def test_no_findings_no_calibration_table(demo_session: GlaiveSession) -> None:
    r = score_session(demo_session, ANSWER_KEY)
    assert r.to_dict()["calibration"] == {}
    assert "Confidence" not in r.to_markdown()
