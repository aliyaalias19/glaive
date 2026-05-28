"""End-to-end agent-loop simulation through the MCP boundary.

Simulates the Hunter agent's full investigation workflow against real
evidence, calling all 5 tools via srv.call_tool() exactly as Claude Code
would. This is the demoable proof that the agentic system works end to end.

Marked integration (uses real Defender.evtx, ~80s).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.server import build_server


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"


def _payload(result):
    """Normalize FastMCP call_tool return to our structured dict."""
    if isinstance(result, list) and result and hasattr(result[0], "text"):
        return json.loads(result[0].text)
    if isinstance(result, dict):
        return result
    raise AssertionError(f"Unexpected call_tool shape: {type(result)}")


@pytest.mark.integration
@pytest.mark.skipif(not REAL_EVTX.exists(), reason="Real Defender.evtx not present.")
class TestFullAgentLoop:
    """The complete investigation, as the agent would drive it."""

    @pytest.mark.asyncio
    async def test_full_investigation_workflow(self, tmp_path: Path) -> None:
        session = GlaiveSession(analysis_dir=tmp_path)
        srv = build_server(session)

        # --- Step 1: agent orients — what evidence is loaded? (nothing yet) ---
        r = _payload(await srv.call_tool("list_evidence", {}))
        assert r["evidence_count"] == 0

        # --- Step 2: agent ingests the Defender log ---
        r = _payload(await srv.call_tool("ingest_artifact", {
            "path": str(REAL_EVTX),
            "source_type": "defender_evtx",
        }))
        assert r["status"] == "ok"
        assert r["nodes_added"] == 10

        # --- Step 3: agent re-checks evidence — now 1 file, chain of custody ---
        r = _payload(await srv.call_tool("list_evidence", {}))
        assert r["evidence_count"] == 1
        assert r["evidence"][0]["original_name"] == "Defender.evtx"
        assert r["graph_totals"]["nodes"] == 10

        # --- Step 4: agent hunts — find Trojan detections ---
        r = _payload(await srv.call_tool("query_graph", {
            "node_type": "AntivirusDetection",
            "filters": [{"field": "threat_name", "op": "contains", "value": "Trojan"}],
        }))
        assert r["status"] == "ok"
        assert r["total_matched"] >= 1
        trojan_key = r["nodes"][0]["canonical_key"]
        threat = r["nodes"][0]["threat_name"]

        # --- Step 5: agent traces the finding to source bytes ---
        r = _payload(await srv.call_tool("get_node_provenance", {
            "canonical_key": trojan_key,
        }))
        assert r["status"] == "ok"
        assert r["source_evidence"]["original_name"] == "Defender.evtx"
        evidence_hash = r["evidence_hash"]

        # --- Step 6: agent commits the finding through the gate ---
        r = _payload(await srv.call_tool("commit_finding", {
            "claim": f"Windows Defender detected {threat} in a downloaded archive",
            "supporting_node_keys": [trojan_key],
            "confidence_hint": "suspected",
        }))
        assert r["committed"] is True
        finding_id = r["finding_id"]

        # --- Step 7: the finding is in the report, with provenance intact ---
        assert len(session.report.findings) == 1
        finding = session.report.findings[0]
        assert finding.finding_id == finding_id
        assert threat in finding.claim
        assert len(finding.supporting_node_keys) == 1

        # --- Bonus: the gate rejects a hallucinated follow-up ---
        r = _payload(await srv.call_tool("commit_finding", {
            "claim": "A process that was never observed exfiltrated data",
            "supporting_node_keys": [["Process", "rd01", 99999, None]],
            "confidence_hint": "confirmed",
        }))
        assert r["committed"] is False
        assert r["decision"] == "rejected_missing_node"
        # Still only the one legitimate finding
        assert len(session.report.findings) == 1

    @pytest.mark.asyncio
    async def test_report_renders_markdown(self, tmp_path: Path) -> None:
        """After the loop, the report renders to markdown for human/judge review."""
        session = GlaiveSession(analysis_dir=tmp_path)
        srv = build_server(session)

        await srv.call_tool("ingest_artifact", {
            "path": str(REAL_EVTX), "source_type": "defender_evtx",
        })
        q = _payload(await srv.call_tool("query_graph", {
            "node_type": "AntivirusDetection",
            "filters": [{"field": "threat_name", "op": "contains", "value": "Trojan"}],
        }))
        key = q["nodes"][0]["canonical_key"]
        await srv.call_tool("commit_finding", {
            "claim": "Defender detected a Trojan",
            "supporting_node_keys": [key],
            "confidence_hint": "suspected",
        })

        md = session.report.to_markdown()
        assert "GLAIVE Investigation Report" in md
        assert "Finding 1" in md
        assert "Defender detected a Trojan" in md
