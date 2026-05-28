"""Tests for the ingest_artifact MCP tool.

Two layers:
  - Helper tests (do_ingest_artifact): fast, synthetic, cover error paths
  - MCP-layer test: proves the closure wiring + call_tool path works
  - Integration test: real Defender.evtx through the helper
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.server import build_server
from glaive.mcp_server.tools import do_ingest_artifact


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    return GlaiveSession(analysis_dir=tmp_path)


# ---- Error paths (fast, no real file) --------------------------------------


class TestIngestErrors:
    def test_unsupported_source_type(self, session: GlaiveSession, tmp_path: Path) -> None:
        f = tmp_path / "something.bin"
        f.write_bytes(b"x")
        result = do_ingest_artifact(session, str(f), "memory_dump")
        assert result["status"] == "error"
        assert result["error"] == "unsupported_source_type"
        assert "memory_dump" in result["message"]

    def test_file_not_found(self, session: GlaiveSession) -> None:
        result = do_ingest_artifact(session, "/nonexistent/path.evtx", "defender_evtx")
        assert result["status"] == "error"
        assert result["error"] == "file_not_found"

    def test_path_is_directory(self, session: GlaiveSession, tmp_path: Path) -> None:
        d = tmp_path / "adir"
        d.mkdir()
        result = do_ingest_artifact(session, str(d), "defender_evtx")
        assert result["status"] == "error"
        assert result["error"] == "not_a_file"

    def test_error_does_not_mutate_graph(self, session: GlaiveSession) -> None:
        """Failed ingest leaves the graph untouched."""
        before = session.graph.node_count()
        do_ingest_artifact(session, "/nope.evtx", "defender_evtx")
        assert session.graph.node_count() == before


# ---- MCP-layer wiring -------------------------------------------------------


class TestMcpLayer:
    @pytest.mark.asyncio
    async def test_tool_is_listed(self, session: GlaiveSession) -> None:
        srv = build_server(session)
        names = [t.name for t in await srv.list_tools()]
        assert "ingest_artifact" in names

    @pytest.mark.asyncio
    async def test_tool_callable_returns_error_for_bad_path(
        self, session: GlaiveSession
    ) -> None:
        """Call the tool through the MCP machinery, not the helper directly."""
        srv = build_server(session)
        result = await srv.call_tool(
            "ingest_artifact",
            {"path": "/does/not/exist.evtx", "source_type": "defender_evtx"},
        )
        # FastMCP may wrap the return; handle both dict and (content, structured) forms
        payload = _extract_payload(result)
        assert payload["status"] == "error"
        assert payload["error"] == "file_not_found"


def _extract_payload(result):
    """FastMCP (mcp 1.27) call_tool returns a list of content blocks.

    For our dict-returning tools, the dict is JSON-serialized into a single
    TextContent block. We parse it back to a dict.
    """
    import json

    if isinstance(result, list) and result:
        block = result[0]
        # TextContent has a .text attribute holding the JSON string
        if hasattr(block, "text"):
            return json.loads(block.text)
    if isinstance(result, dict):
        return result
    raise AssertionError(f"Unexpected call_tool return shape: {type(result)}")


# ---- Integration: real evidence through the helper -------------------------


@pytest.mark.integration
@pytest.mark.skipif(not REAL_EVTX.exists(), reason="Real Defender.evtx not present.")
class TestIngestRealEvidence:
    def test_real_defender_ingest(self, session: GlaiveSession) -> None:
        result = do_ingest_artifact(session, str(REAL_EVTX), "defender_evtx")
        assert result["status"] == "ok"
        assert result["nodes_added"] == 10
        assert result["records_read"] == 15911
        assert result["skipped_event_count"] == 15901
        assert session.graph.node_count() == 10
