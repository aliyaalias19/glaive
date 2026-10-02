"""MCP server: the v0.2 investigation tools."""
from __future__ import annotations

from pathlib import Path

import pytest

from glaive.mcp_server.compat import tool_payload
from glaive.mcp_server.server import build_server
from glaive.mcp_server.session import GlaiveSession


@pytest.mark.asyncio
async def test_new_mcp_tools(demo_session: GlaiveSession) -> None:
    srv = build_server(demo_session)
    overview = tool_payload(await srv.call_tool("case_overview", {}))
    assert "WS-FIN-07.corp.example" in overview["hosts"]
    alerts = tool_payload(await srv.call_tool("list_alerts", {"min_level": "critical"}))
    key = alerts["alerts"][0]["canonical_key"]
    nb = tool_payload(await srv.call_tool("get_neighbors", {"canonical_key": key}))
    assert nb["total"] >= 1
    tl = tool_payload(await srv.call_tool("get_timeline", {"limit": 5}))
    assert tl["returned"] == 5
    saved = tool_payload(await srv.call_tool("save_case", {}))
    assert Path(saved["path"]).exists()


@pytest.mark.asyncio
async def test_mcp_commit_finding_carries_severity_and_attack(demo_session: GlaiveSession) -> None:
    srv = build_server(demo_session)
    proc = tool_payload(await srv.call_tool("query_graph", {
        "node_type": "Process",
        "filters": [{"field": "command_line", "op": "contains", "value": "vssadmin"}]}))
    key = proc["nodes"][0]["canonical_key"]
    res = tool_payload(await srv.call_tool("commit_finding", {
        "claim": "vssadmin.exe deleted all shadow copies.", "supporting_node_keys": [key],
        "severity": "critical", "mitre_techniques": ["T1490"]}))
    assert res["committed"] and res["finding_status"] == "pending_approval"
    f = demo_session.report.findings[-1]
    assert (f.severity, f.mitre_techniques, f.author) == ("critical", ["T1490"], "mcp")
    bad = tool_payload(await srv.call_tool("commit_finding", {
        "claim": "vssadmin.exe sent data to 198.51.100.9", "supporting_node_keys": [key]}))
    assert bad["decision"] == "rejected_ungrounded_claim"
