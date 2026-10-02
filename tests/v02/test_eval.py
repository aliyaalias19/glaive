"""Scoring an investigation against an answer key."""
from __future__ import annotations

from glaive.demo.case import ANSWER_KEY
from glaive.eval import score_session
from glaive.mcp_server import tools
from glaive.mcp_server.session import GlaiveSession


def test_empty_investigation_scores_zero(demo_session: GlaiveSession) -> None:
    r = score_session(demo_session, ANSWER_KEY)
    assert r.recall == 0.0 and r.findings == 0 and r.ungrounded_in_report == 0
    assert "T1490" in r.attack_expected


def test_one_finding_covers_its_answer_key_item(demo_session: GlaiveSession) -> None:
    proc = tools.do_query_graph(demo_session, "Process", filters=[
        {"field": "command_line", "op": "contains", "value": "vssadmin"}])["nodes"][0]
    res = tools.do_commit_finding(
        demo_session, "vssadmin.exe deleted all shadow copies on FILESRV-01.",
        [proc["canonical_key"]], "suspected", severity="critical", mitre_techniques=["T1490"])
    assert res["committed"]
    r = score_session(demo_session, ANSWER_KEY)
    found = {i.id for i in r.items if i.found}
    assert found == {"GT10"}
    assert r.findings == 1 and r.findings_matching == 1 and r.precision_proxy == 1.0
    assert "T1490" in r.attack_found and r.ungrounded_in_report == 0
    assert "| GT10" in r.to_markdown()
    assert r.to_dict()["recall"] == round(1 / len(ANSWER_KEY), 3)


def test_rejected_by_analyst_findings_do_not_count(demo_session: GlaiveSession) -> None:
    proc = tools.do_query_graph(demo_session, "Process", filters=[
        {"field": "command_line", "op": "contains", "value": "vssadmin"}])["nodes"][0]
    tools.do_commit_finding(demo_session, "vssadmin.exe deleted shadow copies.",
                            [proc["canonical_key"]], "suspected")
    f = demo_session.report.findings[0]
    demo_session.report.review(f.finding_id, approve=False, reviewer="analyst")
    assert score_session(demo_session, ANSWER_KEY).findings == 0
