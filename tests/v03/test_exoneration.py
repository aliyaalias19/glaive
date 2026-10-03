"""An AI saying "the host is clean" needs an analyst's approval."""
from __future__ import annotations

import pytest

from glaive.mcp_server import tools
from glaive.mcp_server.session import GlaiveSession
from glaive.reporting.report import is_exoneration


@pytest.mark.parametrize("claim", [
    "No malicious activity was found on WS-FIN-07.",
    "The alerts are false positives caused by the backup agent.",
    "The scheduled task is legitimate: it appears to be benign.",
    "This was an authorised red-team test.",
    "The host is not compromised.",
    "未发现任何恶意活动。",
    "这些告警是误报。",
])
def test_exoneration_claims(claim: str) -> None:
    assert is_exoneration(claim)


@pytest.mark.parametrize("claim", [
    "The Security event log was cleared on FILESRV-01.",
    "Microsoft Defender real-time protection was disabled.",
    "rundll32.exe dumped LSASS memory with comsvcs.dll.",
    "安全日志被清除。",
    "No new services were installed before 09:00, but svc.exe was installed at 09:41.",
])
def test_ordinary_claims(claim: str) -> None:
    assert not is_exoneration(claim)


def _alert_key(s: GlaiveSession) -> list:
    return tools.do_query_graph(s, "Alert", limit=1)["nodes"][0]["canonical_key"]


def test_ai_exoneration_waits_for_an_analyst(demo_session: GlaiveSession) -> None:
    res = tools.do_commit_finding(demo_session, "The alerts on this host are false positives.",
                                  [_alert_key(demo_session)], "inferred", severity="info",
                                  author="hunter")
    assert res["committed"]
    f = demo_session.report.findings[-1]
    assert f.status == "pending_approval" and "benign" in (f.approval_reason or "")
    demo_session.report.review(f.finding_id, False, "lead", "it was real")
    assert f.status == "rejected_by_analyst"


def test_rule_findings_and_ordinary_ai_findings_are_unaffected(demo_session: GlaiveSession) -> None:
    key = _alert_key(demo_session)
    tools.do_commit_finding(demo_session, "A detection rule fired on this host.", [key],
                            "inferred", severity="low", author="hunter")
    tools.do_commit_finding(demo_session, "False positive check: rule fired.", [key],
                            "inferred", severity="low", author="rule:x")
    a, b = demo_session.report.findings[-2:]
    assert a.status == "committed" and a.approval_reason is None
    assert b.status == "committed"  # deterministic rules are not models


def test_high_severity_reason_is_recorded(demo_session: GlaiveSession) -> None:
    tools.do_commit_finding(demo_session, "A detection rule fired on this host.",
                            [_alert_key(demo_session)], "inferred", severity="high",
                            author="hunter")
    assert demo_session.report.findings[-1].approval_reason == "high severity"
