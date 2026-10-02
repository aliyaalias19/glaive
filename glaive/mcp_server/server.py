"""GLAIVE MCP server factory.

build_server(session) returns a FastMCP instance whose tools are closures
capturing the given GlaiveSession (Decision M4). This keeps state explicit
and gives each test an isolated server.

Tools:
  ingest_artifact      feed a file, folder or .zip into the pipeline
  query_graph          read nodes from the graph
  get_node_provenance  trace a node to its source evidence
  commit_finding       THE GATE (the only way to report a finding)
  list_evidence        show loaded evidence (chain of custody)
  case_overview, list_alerts, get_neighbors, get_timeline   navigation (v0.2)
  save_case            persist to the .glaive case file (v0.2)
"""
from __future__ import annotations

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP
except ImportError:  # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP  # type: ignore[no-redef]

from glaive.agents.toolbox import (
    AgentToolbox,
    CaseOverviewArgs,
    ListAlertsArgs,
    NeighborsArgs,
    TimelineArgs,
)
from glaive.mcp_server import tools
from glaive.mcp_server.session import GlaiveSession


def build_server(session: GlaiveSession) -> FastMCP:
    """Construct a FastMCP server bound to the given session.

    All tools capture `session` via closure.
    """
    mcp = FastMCP(name="glaive")

    @mcp.tool()
    def ingest_artifact(path: str, source_type: str = "auto") -> dict:
        """Ingest forensic evidence into the evidence graph.

        Args:
            path: A file, folder or .zip of evidence (EVTX, JSON / JSON-Lines
                log exports). Folders and archives are walked automatically.
            source_type: 'auto' (detect format; runs Sigma + correlation
                rules) or 'defender_evtx' (Windows Defender log only).

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
        severity: str = "medium",
        mitre_techniques: list[str] | None = None,
        rationale: str | None = None,
    ) -> dict:
        """Commit a forensic finding to the investigation report.

        This is the ONLY way to record a finding. Every finding must be backed
        by graph evidence:
          - supporting_node_keys must each resolve to a real graph node
            (obtain them from query_graph, list_alerts or get_neighbors)
          - every IP, path, hash, domain, account or threat name in the claim
            must appear in those nodes or their direct neighbours
          - confidence_hint ('confirmed'/'suspected'/'inferred') is checked
            against graph evidence and downgraded if unsupported
          - severity: info, low, medium, high or critical (high and critical
            wait for an analyst's approval); mitre_techniques e.g. ["T1059.001"]

        Returns a decision: 'accepted', 'downgraded_confidence' (still
        committed, at a lower confidence), 'rejected_missing_node',
        'rejected_empty_support' or 'rejected_ungrounded_claim'. Use the
        reason to self-correct.
        """
        return tools.do_commit_finding(session, claim, supporting_node_keys, confidence_hint,
                                       severity=severity, mitre_techniques=mitre_techniques,
                                       rationale=rationale, author="mcp")

    reader = AgentToolbox(session, readonly=True)

    @mcp.tool()
    def case_overview() -> dict:
        """Summary of the case: hosts, evidence files, node counts, alerts by rule
        and findings so far. Start an investigation here."""
        return reader._overview(CaseOverviewArgs())

    @mcp.tool()
    def list_alerts(min_level: str = "medium", host: str | None = None,
                    rule_contains: str | None = None, limit: int = 25) -> dict:
        """Detection-rule alerts (Sigma + correlations), most severe first.
        min_level: informational, low, medium, high or critical. Each alert has a
        canonical_key you can cite in commit_finding."""
        return reader._alerts(ListAlertsArgs(min_level=min_level, host=host,
                                             rule_contains=rule_contains, limit=limit))

    @mcp.tool()
    def get_neighbors(canonical_key: list, edge_type: str | None = None,
                      limit: int = 40) -> dict:
        """Nodes directly connected to a node (parent/child processes, network
        connections, files written, users, the alerts about it...)."""
        return reader._neighbors(NeighborsArgs(canonical_key=canonical_key,
                                               edge_type=edge_type, limit=limit))

    @mcp.tool()
    def get_timeline(start: str | None = None, end: str | None = None,
                     host: str | None = None, limit: int = 60) -> dict:
        """Chronological events in the case. start/end are ISO-8601 times."""
        return reader._timeline(TimelineArgs(start=start, end=end, host=host, limit=limit))

    @mcp.tool()
    def save_case() -> dict:
        """Save the graph, findings and audit log to the .glaive case file."""
        return {"status": "ok", "path": str(session.save())}

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
