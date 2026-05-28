"""Tests for get_node_provenance + the _coerce_key infrastructure.

The round-trip (string datetime from JSON -> datetime for graph lookup) is
the critical thing being proven here.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.nodes import AntivirusDetection, Process
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.server import build_server
from glaive.mcp_server.tools import (
    _coerce_key,
    _coerce_key_element,
    do_get_node_provenance,
    do_ingest_artifact,
    do_query_graph,
)


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"
VALID_HASH = "a" * 64


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    return GlaiveSession(analysis_dir=tmp_path)


# ---- _coerce_key ------------------------------------------------------------


class TestCoerceKey:
    def test_iso_datetime_string_becomes_datetime(self) -> None:
        result = _coerce_key_element("2025-04-12T08:21:44.894831+00:00")
        assert isinstance(result, datetime)
        assert result.year == 2025

    def test_threat_name_string_stays_string(self) -> None:
        result = _coerce_key_element("Trojan:Win32/Cloxer")
        assert result == "Trojan:Win32/Cloxer"

    def test_int_stays_int(self) -> None:
        assert _coerce_key_element(1116) == 1116

    def test_hostname_stays_string(self) -> None:
        assert _coerce_key_element("DESKTOP-RFOH5TL") == "DESKTOP-RFOH5TL"

    def test_none_stays_none(self) -> None:
        assert _coerce_key_element(None) is None

    def test_full_key_coercion(self) -> None:
        raw = ["AntivirusDetection", "rd01", 1116,
               "2025-04-12T08:21:44.894831+00:00", "Trojan:Win32/Cloxer"]
        coerced = _coerce_key(raw)
        assert isinstance(coerced, tuple)
        assert coerced[0] == "AntivirusDetection"
        assert coerced[2] == 1116
        assert isinstance(coerced[3], datetime)
        assert coerced[4] == "Trojan:Win32/Cloxer"

    def test_coerced_key_matches_graph_node(self, session: GlaiveSession) -> None:
        """The actual purpose: a coerced key resolves a real node."""
        when = datetime(2025, 4, 12, 8, 21, 44, 894831, tzinfo=timezone.utc)
        node = AntivirusDetection(
            evidence_hash=VALID_HASH, derivation="t", host_hostname="rd01",
            event_id=1116, threat_name="Trojan:Win32/Cloxer", detection_time=when,
        )
        session.graph.add_node(node)

        # Simulate the agent sending back the serialized key
        serialized = [
            (e.isoformat() if hasattr(e, "isoformat") else e)
            for e in node.canonical_key()
        ]
        coerced = _coerce_key(serialized)
        assert session.graph.has_node(coerced)


# ---- do_get_node_provenance ------------------------------------------------


class TestProvenance:
    def test_missing_node_returns_error(self, session: GlaiveSession) -> None:
        result = do_get_node_provenance(session, ["Process", "rd01", 9999, None])
        assert result["status"] == "error"
        assert result["error"] == "node_not_found"

    def test_provenance_has_core_fields(self, session: GlaiveSession) -> None:
        p = Process(
            evidence_hash=VALID_HASH, derivation="vol psscan", host_hostname="rd01",
            pid=1912, name="STUN.exe",
            start_time=datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc),
            observed_by=["psscan", "pslist"],
        )
        session.graph.add_node(p)
        serialized = [
            (e.isoformat() if hasattr(e, "isoformat") else e)
            for e in p.canonical_key()
        ]
        result = do_get_node_provenance(session, serialized)
        assert result["status"] == "ok"
        assert result["evidence_hash"] == VALID_HASH
        assert result["derivation"] == "vol psscan"
        assert sorted(result["observed_by"]) == ["pslist", "psscan"]

    def test_result_json_serializable(self, session: GlaiveSession) -> None:
        p = Process(
            evidence_hash=VALID_HASH, derivation="t", host_hostname="rd01",
            pid=1912, name="STUN.exe",
            start_time=datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc),
        )
        session.graph.add_node(p)
        serialized = [
            (e.isoformat() if hasattr(e, "isoformat") else e)
            for e in p.canonical_key()
        ]
        result = do_get_node_provenance(session, serialized)
        json.dumps(result)  # must not raise


# ---- MCP layer + integration -----------------------------------------------


class TestMcpLayer:
    @pytest.mark.asyncio
    async def test_through_call_tool(self, session: GlaiveSession) -> None:
        p = Process(
            evidence_hash=VALID_HASH, derivation="t", host_hostname="rd01",
            pid=1912, name="STUN.exe",
            start_time=datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc),
        )
        session.graph.add_node(p)
        serialized = [
            (e.isoformat() if hasattr(e, "isoformat") else e)
            for e in p.canonical_key()
        ]
        srv = build_server(session)
        result = await srv.call_tool("get_node_provenance", {"canonical_key": serialized})
        payload = _extract_payload(result)
        assert payload["status"] == "ok"


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
class TestProvenanceRealEvidence:
    def test_trace_real_finding_to_source(self, session: GlaiveSession) -> None:
        do_ingest_artifact(session, str(REAL_EVTX), "defender_evtx")
        q = do_query_graph(session, node_type="AntivirusDetection",
                           filters=[{"field": "threat_name", "op": "contains", "value": "Trojan"}])
        key = q["nodes"][0]["canonical_key"]
        prov = do_get_node_provenance(session, key)
        assert prov["status"] == "ok"
        assert prov["source_evidence"]["original_name"] == "Defender.evtx"
        assert prov["source_evidence"]["size_bytes"] > 0
