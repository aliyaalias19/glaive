"""Tests for the query_graph MCP tool.

Focus areas:
  - Filter interpreter (_matches_filter): each op, missing fields, type mismatches
  - canonical_key datetime serialization (the bug we caught)
  - Result limiting / truncation (resource bound)
  - Bad filter op feedback
  - MCP-layer round trip
  - Integration: real Trojan query
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.nodes import AntivirusDetection, Host, Process
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.server import build_server
from glaive.mcp_server.tools import (
    _matches_filter,
    do_ingest_artifact,
    do_query_graph,
)


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"
VALID_HASH = "a" * 64


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    return GlaiveSession(analysis_dir=tmp_path)


def _add_av(session: GlaiveSession, threat: str, eid: int, when: datetime) -> None:
    session.graph.add_node(
        AntivirusDetection(
            evidence_hash=VALID_HASH,
            derivation="test",
            host_hostname="rd01",
            event_id=eid,
            threat_name=threat,
            detection_time=when,
        )
    )


# ---- Filter interpreter unit tests -----------------------------------------


class TestMatchesFilter:
    def _proc(self) -> Process:
        return Process(
            evidence_hash=VALID_HASH, derivation="t", host_hostname="rd01",
            pid=1912, name="STUN.exe",
            start_time=datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc),
        )

    def test_eq_match(self) -> None:
        assert _matches_filter(self._proc(), {"field": "name", "op": "eq", "value": "STUN.exe"})

    def test_eq_no_match(self) -> None:
        assert not _matches_filter(self._proc(), {"field": "name", "op": "eq", "value": "other.exe"})

    def test_contains_match(self) -> None:
        assert _matches_filter(self._proc(), {"field": "name", "op": "contains", "value": "STUN"})

    def test_gt_match(self) -> None:
        assert _matches_filter(self._proc(), {"field": "pid", "op": "gt", "value": 1000})

    def test_lt_no_match(self) -> None:
        assert not _matches_filter(self._proc(), {"field": "pid", "op": "lt", "value": 1000})

    def test_missing_field_never_matches(self) -> None:
        assert not _matches_filter(self._proc(), {"field": "threat_name", "op": "eq", "value": "x"})

    def test_exists_true_for_present_field(self) -> None:
        assert _matches_filter(self._proc(), {"field": "name", "op": "exists", "value": True})

    def test_exists_false_for_absent_field(self) -> None:
        assert _matches_filter(self._proc(), {"field": "threat_name", "op": "exists", "value": False})

    def test_type_mismatch_does_not_raise(self) -> None:
        # gt comparing int field to a string value -> no match, no crash
        assert not _matches_filter(self._proc(), {"field": "pid", "op": "gt", "value": "abc"})

    def test_contains_on_non_iterable_does_not_raise(self) -> None:
        # contains against an int field -> no match, no crash
        assert not _matches_filter(self._proc(), {"field": "pid", "op": "contains", "value": 9})

    def test_unknown_op_returns_false(self) -> None:
        assert not _matches_filter(self._proc(), {"field": "name", "op": "regex", "value": ".*"})


# ---- do_query_graph --------------------------------------------------------


class TestDoQueryGraph:
    def test_empty_graph_returns_zero(self, session: GlaiveSession) -> None:
        result = do_query_graph(session)
        assert result["status"] == "ok"
        assert result["total_matched"] == 0
        assert result["nodes"] == []

    def test_node_type_filter(self, session: GlaiveSession) -> None:
        session.graph.add_node(Host(evidence_hash=VALID_HASH, derivation="t", hostname="rd01"))
        _add_av(session, "Trojan:Win32/X", 1116, datetime(2025, 1, 1, tzinfo=timezone.utc))
        result = do_query_graph(session, node_type="AntivirusDetection")
        assert result["total_matched"] == 1
        assert result["nodes"][0]["node_type"] == "AntivirusDetection"

    def test_field_filter(self, session: GlaiveSession) -> None:
        _add_av(session, "Trojan:Win32/Cloxer", 1116, datetime(2025, 1, 1, tzinfo=timezone.utc))
        _add_av(session, "PUA:Win32/Other", 1116, datetime(2025, 1, 2, tzinfo=timezone.utc))
        result = do_query_graph(
            session,
            node_type="AntivirusDetection",
            filters=[{"field": "threat_name", "op": "contains", "value": "Trojan"}],
        )
        assert result["total_matched"] == 1

    def test_result_is_json_serializable(self, session: GlaiveSession) -> None:
        """The datetime-in-canonical_key bug regression test."""
        _add_av(session, "Trojan:Win32/X", 1116, datetime(2025, 4, 12, 8, 21, 44, tzinfo=timezone.utc))
        result = do_query_graph(session, node_type="AntivirusDetection")
        # Must not raise
        json.dumps(result)
        # canonical_key datetime element is a string
        key = result["nodes"][0]["canonical_key"]
        assert isinstance(key[3], str)
        assert "2025-04-12" in key[3]

    def test_limit_truncates(self, session: GlaiveSession) -> None:
        for i in range(5):
            _add_av(session, f"Threat{i}", 1116, datetime(2025, 1, 1, i, tzinfo=timezone.utc))
        result = do_query_graph(session, node_type="AntivirusDetection", limit=2)
        assert result["total_matched"] == 5
        assert result["returned"] == 2
        assert result["truncated"] is True

    def test_bad_filter_op_returns_error(self, session: GlaiveSession) -> None:
        result = do_query_graph(
            session,
            filters=[{"field": "name", "op": "regex", "value": ".*"}],
        )
        assert result["status"] == "error"
        assert result["error"] == "bad_filter_op"


# ---- MCP layer -------------------------------------------------------------


class TestMcpLayer:
    @pytest.mark.asyncio
    async def test_query_through_call_tool(self, session: GlaiveSession) -> None:
        _add_av(session, "Trojan:Win32/X", 1116, datetime(2025, 1, 1, tzinfo=timezone.utc))
        srv = build_server(session)
        result = await srv.call_tool("query_graph", {"node_type": "AntivirusDetection"})
        payload = _extract_payload(result)
        assert payload["status"] == "ok"
        assert payload["total_matched"] == 1


def _extract_payload(result):
    if isinstance(result, list) and result:
        block = result[0]
        if hasattr(block, "text"):
            return json.loads(block.text)
    if isinstance(result, dict):
        return result
    raise AssertionError(f"Unexpected call_tool return shape: {type(result)}")


# ---- Integration -----------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(not REAL_EVTX.exists(), reason="Real Defender.evtx not present.")
class TestQueryRealEvidence:
    def test_real_trojan_query(self, session: GlaiveSession) -> None:
        do_ingest_artifact(session, str(REAL_EVTX), "defender_evtx")
        result = do_query_graph(
            session,
            node_type="AntivirusDetection",
            filters=[{"field": "threat_name", "op": "contains", "value": "Trojan"}],
        )
        assert result["status"] == "ok"
        assert result["total_matched"] >= 1
        # Every matched node carries the real evidence hash
        for node in result["nodes"]:
            assert node["evidence_hash"]
            assert "Trojan" in node["threat_name"]
