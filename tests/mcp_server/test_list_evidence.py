"""Tests for the list_evidence MCP tool — chain-of-custody view."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.server import build_server
from glaive.mcp_server.tools import do_ingest_artifact, do_list_evidence


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    return GlaiveSession(analysis_dir=tmp_path)


class TestListEvidence:
    def test_empty_session(self, session: GlaiveSession) -> None:
        result = do_list_evidence(session)
        assert result["status"] == "ok"
        assert result["evidence_count"] == 0
        assert result["ingest_runs"] == 0
        assert result["evidence"] == []

    def test_lists_ingested_file(self, session: GlaiveSession, tmp_path: Path) -> None:
        # Ingest a tiny fake file directly via the store to avoid EVTX parsing
        f = tmp_path / "sample.evtx"
        f.write_bytes(b"fake evtx bytes")
        sha = session.store.ingest(f)

        result = do_list_evidence(session)
        assert result["evidence_count"] == 1
        item = result["evidence"][0]
        assert item["evidence_hash"] == sha
        assert item["original_name"] == "sample.evtx"
        assert item["size_bytes"] == len(b"fake evtx bytes")

    def test_result_json_serializable(self, session: GlaiveSession, tmp_path: Path) -> None:
        f = tmp_path / "x.evtx"
        f.write_bytes(b"data")
        session.store.ingest(f)
        json.dumps(do_list_evidence(session))  # must not raise

    def test_sorted_by_ingest_time(self, session: GlaiveSession, tmp_path: Path) -> None:
        for name in ["a.evtx", "b.evtx", "c.evtx"]:
            f = tmp_path / name
            f.write_bytes(name.encode())  # distinct content -> distinct hash
            session.store.ingest(f)
        result = do_list_evidence(session)
        times = [e["ingested_at"] for e in result["evidence"]]
        assert times == sorted(times)


class TestMcpLayer:
    @pytest.mark.asyncio
    async def test_through_call_tool(self, session: GlaiveSession) -> None:
        srv = build_server(session)
        result = await srv.call_tool("list_evidence", {})
        payload = _extract_payload(result)
        assert payload["status"] == "ok"
        assert payload["evidence_count"] == 0


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
class TestListRealEvidence:
    def test_real_file_appears(self, populated_session: GlaiveSession) -> None:
        result = do_list_evidence(populated_session)
        assert result["evidence_count"] == 1
        assert result["evidence"][0]["original_name"] == "Defender.evtx"
        assert result["ingest_runs"] == 1
