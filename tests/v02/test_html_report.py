"""The standalone HTML report."""
from __future__ import annotations

from glaive.mcp_server import tools
from glaive.mcp_server.session import GlaiveSession
from glaive.reporting.html import render_html


def test_html_report_escapes_attacker_text(demo_session: GlaiveSession) -> None:
    key = tools.do_query_graph(demo_session, "Host")["nodes"][0]["canonical_key"]
    tools.do_commit_finding(demo_session, "<script>alert(1)</script> appeared in a log", [key],
                            "inferred")
    page = render_html(demo_session)
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page
    assert "Evidence and chain of custody" in page
