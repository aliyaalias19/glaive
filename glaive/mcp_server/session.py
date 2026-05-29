"""GlaiveSession — per-investigation shared state for the MCP server.

One session holds everything an investigation needs: the evidence graph,
the content-addressed store, the ingestion orchestrator, and the finding
report (with its gate).

Decision M2: stateful server, one session per server lifetime.
Decision M4: tools capture the session via closure (see server.py).
"""
from __future__ import annotations

from pathlib import Path

from glaive.evidence.store import EvidenceStore
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.orchestrator import Orchestrator
from glaive.reporting.report import FindingReport


class GlaiveSession:
    """All state for one forensic investigation.

    Construct once per MCP server. The default analysis_dir places the
    evidence store under ./analysis/evidence_store/ (Protocol SIFT convention, D7).
    """

    def __init__(
        self,
        analysis_dir: Path | None = None,
        evidence_root: Path | None = None,
    ) -> None:
        """
        Args:
            analysis_dir: Where the evidence store and reports live.
                Defaults to ./analysis.
            evidence_root: Optional allowlist for ingest paths. When set,
                ingest_artifact rejects paths outside this directory
                (after symlink resolution). When None, no path restriction
                (default; matches Day-6 behavior).
        """
        self.analysis_dir = Path(analysis_dir) if analysis_dir else Path("./analysis")
        self.evidence_store_dir = self.analysis_dir / "evidence_store"
        self.evidence_root = (
            Path(evidence_root).resolve() if evidence_root else None
        )

        self.graph = EvidenceGraph()
        self.store = EvidenceStore(self.evidence_store_dir)
        self.orchestrator = Orchestrator(self.graph, self.store)
        self.report = FindingReport()

    def stats(self) -> dict:
        """Quick snapshot of session state — used by tools for status replies."""
        return {
            "graph_nodes": self.graph.node_count(),
            "graph_edges": self.graph.edge_count(),
            "evidence_files": len(self.store),
            "findings_committed": len(self.report.findings),
            "ingest_runs": len(self.orchestrator.reports),
        }
