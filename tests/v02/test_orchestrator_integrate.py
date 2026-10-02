"""Orchestrator.integrate: adding an already-parsed result to the graph."""
from __future__ import annotations

from pathlib import Path

from glaive.evidence.store import EvidenceStore
from glaive.graph.edges import Spawned
from glaive.graph.nodes import Host, Process
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.base import ParseResult
from glaive.ingestion.orchestrator import Orchestrator
from glaive.ingestion.windows import WindowsParseResult

H = "a" * 64


def _proc(pid: int) -> Process:
    return Process(evidence_hash=H, derivation="t", host_hostname="h", pid=pid, name=f"p{pid}.exe")


def test_integrate_adds_and_merges(tmp_path: Path) -> None:
    orch = Orchestrator(EvidenceGraph(), EvidenceStore(tmp_path))
    result = ParseResult(nodes=[Host(evidence_hash=H, derivation="t", hostname="h"), _proc(1)])
    first = orch.integrate("Test", result)
    second = orch.integrate("Test", result)
    assert (first.nodes_added, second.nodes_merged) == (2, 2)
    assert orch.graph.node_count() == 2 and len(orch.reports) == 2


def test_orphan_edges_are_counted_not_silently_dropped(tmp_path: Path) -> None:
    orch = Orchestrator(EvidenceGraph(), EvidenceStore(tmp_path))
    a, b = _proc(1), _proc(2)
    edge = Spawned(evidence_hash=H, derivation="t", source_key=a.canonical_key(),
                   target_key=b.canonical_key())
    report = orch.integrate("Test", ParseResult(nodes=[a], edges=[edge]))
    assert report.edges_added == 0
    assert report.parser_stats["orphan_edges_skipped"] == 1


def test_per_event_links_are_not_copied_into_stats(tmp_path: Path) -> None:
    orch = Orchestrator(EvidenceGraph(), EvidenceStore(tmp_path))
    result = WindowsParseResult(event_entities={"u1": []}, events_used=3)
    stats = orch.integrate("WindowsEventParser", result).parser_stats
    assert stats["events_used"] == 3 and "event_entities" not in stats
