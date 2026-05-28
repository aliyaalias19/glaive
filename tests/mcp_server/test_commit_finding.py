"""Tests for the commit_finding MCP tool — the architectural gate at the
MCP boundary.

The gate logic itself is tested in tests/reporting/test_report.py. These
tests verify the TOOL correctly wires the gate: key coercion, commit-on-accept,
commit-on-downgrade, no-commit-on-reject, and decision feedback.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.edges import Spawned
from glaive.graph.nodes import AntivirusDetection, Process
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.server import build_server
from glaive.mcp_server.tools import do_commit_finding, do_ingest_artifact, do_query_graph


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"
VALID_HASH = "a" * 64
SVCHOST_START = datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc)
STUN_START = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    return GlaiveSession(analysis_dir=tmp_path)


@pytest.fixture
def session_with_confirmed_spawn(tmp_path: Path) -> tuple[GlaiveSession, list]:
    """Session with svchost -> STUN confirmed Spawned edge. Returns the
    serialized svchost key for use as a supporting key."""
    s = GlaiveSession(analysis_dir=tmp_path)
    svchost = Process(
        evidence_hash=VALID_HASH, derivation="psscan", host_hostname="rd01",
        pid=1244, name="svchost.exe", start_time=SVCHOST_START,
    )
    s.graph.add_node(svchost)
    stun = Process(
        evidence_hash=VALID_HASH, derivation="psscan", host_hostname="rd01",
        pid=1912, name="STUN.exe", start_time=STUN_START,
    )
    s.graph.add_node(stun)
    s.graph.add_edge(Spawned(
        evidence_hash=VALID_HASH, derivation="pstree+evtx_4688",
        source_key=svchost.canonical_key(), target_key=stun.canonical_key(),
        timestamp=STUN_START, confirmed_by=["pstree", "evtx_4688"],
    ))
    serialized = [
        (e.isoformat() if hasattr(e, "isoformat") else e)
        for e in svchost.canonical_key()
    ]
    return s, serialized


# ---- Rejections ------------------------------------------------------------


class TestRejections:
    def test_empty_support_rejected(self, session: GlaiveSession) -> None:
        result = do_commit_finding(session, "vague claim", [], "confirmed")
        assert result["status"] == "rejected"
        assert result["decision"] == "rejected_empty_support"
        assert result["committed"] is False
        assert result["total_findings"] == 0

    def test_hallucinated_key_rejected(self, session: GlaiveSession) -> None:
        result = do_commit_finding(
            session, "fake process claim",
            [["Process", "rd01", 99999, None]], "confirmed",
        )
        assert result["status"] == "rejected"
        assert result["decision"] == "rejected_missing_node"
        assert result["committed"] is False

    def test_bad_confidence_hint_errors(self, session: GlaiveSession) -> None:
        result = do_commit_finding(session, "x", [["Host", "rd01"]], "totally_sure")
        assert result["status"] == "error"
        assert result["error"] == "bad_confidence_hint"


# ---- Accept + downgrade ----------------------------------------------------


class TestAcceptAndDowngrade:
    def test_confirmed_evidence_accepted(self, session_with_confirmed_spawn) -> None:
        s, svchost_key = session_with_confirmed_spawn
        result = do_commit_finding(
            s, "svchost.exe spawned STUN.exe", [svchost_key], "confirmed",
        )
        assert result["status"] == "ok"
        assert result["decision"] == "accepted"
        assert result["committed"] is True
        assert result["final_confidence"] == "confirmed"
        assert result["total_findings"] == 1

    def test_overclaim_downgraded_but_committed(self, session_with_confirmed_spawn) -> None:
        """Edge is confirmed (2 sources). If agent claims 'confirmed' it's
        accepted. To test downgrade we claim on a node whose edges are weaker —
        here we use a standalone node with no edges -> inferred."""
        s, _ = session_with_confirmed_spawn
        # A standalone AV detection node: no edges -> evidence supports 'inferred'
        av = AntivirusDetection(
            evidence_hash=VALID_HASH, derivation="defender", host_hostname="rd01",
            event_id=1116, threat_name="Trojan:Win32/X",
            detection_time=datetime(2025, 4, 12, tzinfo=timezone.utc),
        )
        s.graph.add_node(av)
        av_key = [
            (e.isoformat() if hasattr(e, "isoformat") else e)
            for e in av.canonical_key()
        ]
        result = do_commit_finding(s, "Trojan detected", [av_key], "confirmed")
        assert result["decision"] == "downgraded_confidence"
        assert result["committed"] is True  # M11: downgrade still commits
        assert result["final_confidence"] == "inferred"
        assert result["agent_confidence_hint"] == "confirmed"

    def test_key_coercion_allows_datetime_keys(self, session_with_confirmed_spawn) -> None:
        """The svchost key has a datetime; serialized form must still resolve."""
        s, svchost_key = session_with_confirmed_spawn
        # svchost_key[3] is an isoformat string
        assert isinstance(svchost_key[3], str)
        result = do_commit_finding(s, "claim", [svchost_key], "suspected")
        # If coercion failed, this would be rejected_missing_node
        assert result["committed"] is True


# ---- MCP layer + integration -----------------------------------------------


class TestMcpLayer:
    @pytest.mark.asyncio
    async def test_commit_through_call_tool(self, session_with_confirmed_spawn) -> None:
        s, svchost_key = session_with_confirmed_spawn
        srv = build_server(s)
        result = await srv.call_tool("commit_finding", {
            "claim": "svchost spawned STUN",
            "supporting_node_keys": [svchost_key],
            "confidence_hint": "confirmed",
        })
        payload = _extract_payload(result)
        assert payload["committed"] is True


def _extract_payload(result):
    if isinstance(result, list) and result:
        block = result[0]
        if hasattr(block, "text"):
            return json.loads(block.text)
    if isinstance(result, dict):
        return result
    raise AssertionError(f"Unexpected shape: {type(result)}")


@pytest.mark.integration
@pytest.mark.skipif(not REAL_EVTX.exists(), reason="Real Defender.evtx not present.")
class TestCommitRealEvidence:
    def test_commit_real_trojan_finding(self, session: GlaiveSession) -> None:
        do_ingest_artifact(session, str(REAL_EVTX), "defender_evtx")
        q = do_query_graph(session, node_type="AntivirusDetection",
                           filters=[{"field": "threat_name", "op": "contains", "value": "Trojan"}])
        key = q["nodes"][0]["canonical_key"]
        result = do_commit_finding(
            session, "Defender detected Trojan:Win32/Cloxer", [key], "suspected",
        )
        assert result["committed"] is True
        assert session.report.findings[0].claim.startswith("Defender detected")
