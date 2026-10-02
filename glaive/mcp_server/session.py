"""GlaiveSession - per-investigation shared state.

One session holds everything an investigation needs: the evidence graph,
the content-addressed store, the ingestion orchestrator, the finding report
(with its gate), an audit log, and an event bus the web UI listens to.

Decision M2: stateful server, one session per server lifetime.
Decision M4: tools capture the session via closure (see server.py).

v0.2: sessions can be saved to and reopened from a .glaive case file
(analysis_dir/case.glaive), so an investigation survives restarts.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from glaive.evidence.store import EvidenceStore
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.orchestrator import Orchestrator
from glaive.reporting.report import Finding, FindingReport

CASE_FILENAME = "case.glaive"


class GlaiveSession:
    """All state for one forensic investigation.

    Construct once per MCP server / web app / CLI run. The default
    analysis_dir places the evidence store under ./analysis/evidence_store/
    (Protocol SIFT convention, D7).
    """

    def __init__(
        self,
        analysis_dir: Path | None = None,
        evidence_root: Path | None = None,
        case_name: str | None = None,
    ) -> None:
        """
        Args:
            analysis_dir: Where the evidence store, case file and reports live.
                Defaults to ./analysis.
            evidence_root: Optional allowlist for ingest paths. When set,
                ingest_artifact rejects paths outside this directory
                (after symlink resolution).
            case_name: Human-friendly case title.
        """
        self.analysis_dir = Path(analysis_dir) if analysis_dir else Path("./analysis")
        self.evidence_store_dir = self.analysis_dir / "evidence_store"
        self.evidence_root = Path(evidence_root).resolve() if evidence_root else None
        self.case_name = case_name or self.analysis_dir.resolve().name

        self.graph = EvidenceGraph()
        self.store = EvidenceStore(self.evidence_store_dir)
        self.orchestrator = Orchestrator(self.graph, self.store)
        self.report = FindingReport()

        self.summary_markdown: str | None = None
        self.audit_log: list[dict[str, Any]] = []
        self._unsaved_audit: list[dict[str, Any]] = []
        self._subscribers: list[Callable[[dict[str, Any]], None]] = []
        self._lock = threading.RLock()

        self.report.subscribe(self._on_finding_event)

    # ---- events / audit ----------------------------------------------------------

    @property
    def case_path(self) -> Path:
        return self.analysis_dir / CASE_FILENAME

    def subscribe(self, fn: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        """Receive every audit event (used by the web UI's live stream).
        Returns a function that unsubscribes."""
        self._subscribers.append(fn)
        return lambda: self._subscribers.remove(fn) if fn in self._subscribers else None

    def log(self, actor: str, action: str, **detail: Any) -> dict[str, Any]:
        """Record an audit event and notify subscribers."""
        entry = {"ts": datetime.now(UTC).isoformat(), "actor": actor,
                 "action": action, "detail": detail}
        with self._lock:
            self.audit_log.append(entry)
            self._unsaved_audit.append(entry)
        for fn in list(self._subscribers):
            try:
                fn(entry)
            except Exception:
                pass
        return entry

    def _on_finding_event(self, event: str, finding: Finding) -> None:
        self.log(finding.author if event == "committed" else (finding.reviewed_by or "skeptic"),
                 f"finding_{event}", finding_id=finding.finding_id, claim=finding.claim,
                 confidence=finding.confidence, severity=finding.severity,
                 status=finding.status)

    # ---- persistence ---------------------------------------------------------------

    def save(self) -> Path:
        """Write graph, findings, evidence manifest and new audit entries to
        analysis_dir/case.glaive. Safe to call repeatedly."""
        from glaive.case import CaseFile

        with self._lock, CaseFile(self.case_path) as cf:
            cf.set_meta("case_name", self.case_name)
            if self.summary_markdown:
                cf.set_meta("summary_markdown", self.summary_markdown)
            cf.write_snapshot(self.graph.to_dict(), self.report.to_dict(), self.store.list_all())
            if self._unsaved_audit:
                cf.append_audit(self._unsaved_audit)
                self._unsaved_audit = []
        return self.case_path

    @classmethod
    def load(cls, path: Path, evidence_root: Path | None = None) -> GlaiveSession:
        """Reopen a saved investigation. `path` is the .glaive file or its folder."""
        from glaive.case import CaseFile, CaseFileError

        path = Path(path)
        case_path = path / CASE_FILENAME if path.is_dir() else path
        if not case_path.exists():
            raise CaseFileError(f"No case file at {case_path}")
        with CaseFile(case_path) as cf:
            session = cls(analysis_dir=case_path.parent, evidence_root=evidence_root,
                          case_name=cf.get_meta("case_name"))
            graph = cf.read_snapshot("graph")
            report = cf.read_snapshot("report")
            session.audit_log = cf.audit()
            session.summary_markdown = cf.get_meta("summary_markdown")
        if graph:
            session.graph = EvidenceGraph.from_dict(graph)
            session.orchestrator = Orchestrator(session.graph, session.store)
        if report:
            session.report = FindingReport.from_dict(report)
            session.report.subscribe(session._on_finding_event)
        return session

    # ---- status --------------------------------------------------------------------

    def stats(self) -> dict:
        """Quick snapshot of session state - used by tools for status replies."""
        return {
            "case_name": self.case_name,
            "graph_nodes": self.graph.node_count(),
            "graph_edges": self.graph.edge_count(),
            "node_types": self.graph.type_counts(),
            "evidence_files": len(self.store),
            "findings_committed": len(self.report.findings),
            "findings_pending_approval": len(self.report.pending()),
            "ingest_runs": len(self.orchestrator.reports),
        }
