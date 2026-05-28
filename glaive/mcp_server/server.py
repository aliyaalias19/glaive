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

    @mcp.tool()
    def query_graph(
        node_type: str | None = None,
        filters: list[dict] | None = None,
        limit: int = 100,
    ) -> dict:
        """Query the evidence graph for nodes matching declarative filters.

        Args:
            node_type: Optional node type to filter by (e.g. 'Process',
                'AntivirusDetection', 'File', 'RegistryKey').
            filters: Optional list of filters, each {"field","op","value"},
                AND-combined. Supported ops: eq, contains, gt, lt, exists.
            limit: Max nodes returned (default 100).

        Returns matched node summaries including canonical_key (usable in
        commit_finding and get_node_provenance) and evidence_hash.
        """
        return tools.do_query_graph(session, node_type, filters, limit)

    @mcp.tool()
    def get_node_provenance(canonical_key: list) -> dict:
        """Trace a graph node back to its source evidence.

        Args:
            canonical_key: The node's key (as returned by query_graph).

        Returns the full provenance chain: evidence_hash, derivation, the
        source file's name and size, and (for multi-source nodes) the list
        of tools that observed the node. This is how any finding is traced
        to the bytes that produced it.
        """
        return tools.do_get_node_provenance(session, canonical_key)

    @mcp.tool()
    def commit_finding(
        claim: str,
        supporting_node_keys: list,
        confidence_hint: str = "suspected",
    ) -> dict:
        """Commit a forensic finding to the investigation report.

        This is the ONLY way to record a finding. Every finding must be backed
        by graph evidence:
          - supporting_node_keys must each resolve to a real graph node
            (obtain them from query_graph)
          - confidence_hint ('confirmed'/'suspected'/'inferred'/'disputed') is
            checked against graph evidence and downgraded if unsupported

        Returns a decision: 'accepted', 'downgraded_confidence' (still
        committed, at a lower confidence), 'rejected_missing_node', or
        'rejected_empty_support'. Use the reason to self-correct.
        """
        return tools.do_commit_finding(session, claim, supporting_node_keys, confidence_hint)

    @mcp.tool()
    def list_evidence() -> dict:
        """List all evidence ingested into this investigation.

        Returns each evidence file's hash, original name, size, and ingest
        time — the chain-of-custody view — plus current graph totals.
        """
        return tools.do_list_evidence(session)

    # Expose session on the server object for test access
    mcp._glaive_session = session  # type: ignore[attr-defined]

    return mcp
