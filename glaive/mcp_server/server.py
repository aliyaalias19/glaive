"""GLAIVE MCP server factory.

build_server(session) returns a FastMCP instance whose tools are closures
capturing the given GlaiveSession (Decision M4). This keeps state explicit
and gives each test an isolated server.

The 5 v1 tools (Decision M1, D3) are registered here:
  1. ingest_artifact      — feed evidence into the pipeline
  2. query_graph          — read nodes from the graph
  3. get_node_provenance  — trace a node to its source evidence
  4. commit_finding       — THE GATE (only way to report a finding)
  5. list_evidence        — show loaded evidence

Tools are added incrementally (Steps 3-7). This file starts with none.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server import tools


def build_server(session: GlaiveSession) -> FastMCP:
    """Construct a FastMCP server bound to the given session.

    All tools capture `session` via closure.
    """
    mcp = FastMCP(name="glaive")

    @mcp.tool()
    def ingest_artifact(path: str, source_type: str) -> dict:
        """Ingest a forensic artifact into the evidence graph.

        Args:
            path: Filesystem path to the evidence file.
            source_type: The kind of evidence. Currently supported:
                'defender_evtx' (Windows Defender Operational event log).

        Returns a summary dict: nodes added, evidence hash, records read,
        and how many records were skipped as unsupported event types.
        """
        return tools.do_ingest_artifact(session, path, source_type)

    # Expose session on the server object for test access
    mcp._glaive_session = session  # type: ignore[attr-defined]

    return mcp
