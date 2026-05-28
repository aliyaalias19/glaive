"""Tests for the orchestrator — the integration layer that wires
evidence store + parsers + graph into one pipeline.

The key end-to-end test: ingest a real Defender.evtx file (well, our
synthetic stand-in), confirm that:
  - Evidence is hashed and stored
  - Parser is called with the injected hash
  - Resulting nodes carry the correct evidence_hash
  - Graph is populated correctly
  - Report stats reflect actual graph operations
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.evidence.store import EvidenceStore, hash_file
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.defender import DefenderEvtxParser
from glaive.ingestion.orchestrator import IngestReport, Orchestrator
from glaive.ingestion.volatility import VolatilityProcessParser


VALID_HASH = "a" * 64


def _defender_event(
    event_id: int = 1117,
    time_created: str = "2023-01-25T15:00:00+00:00",
    threat_name: str = "Trojan:Win32/PowerRunner.A",
    action: str = "Quarantined",
    file_path: str = "C:\\Users\\rsydow\\AppData\\Local\\Temp\\msedge.exe",
) -> dict:
    """Helper — note no _evidence_hash; orchestrator will inject it."""
    return {
        "event_id": event_id,
        "time_created": time_created,
        "computer": "rd01",
        "threat_name": threat_name,
        "action": action,
        "file_path": file_path,
    }


def _proc(
    pid: int,
    name: str,
    start_time: str | None = None,
    parent_pid: int | None = None,
) -> dict:
    return {
        "pid": pid,
        "name": name,
        "image_path": None,
        "command_line": None,
        "parent_pid": parent_pid,
        "start_time": start_time,
        "exit_time": None,
        "_host_hostname": "rd01",
        # Note: no _evidence_hash or _derivation — orchestrator injects
    }


def _pstree(parent_pid: int, child_pid: int, child_start_time: str | None) -> dict:
    return {
        "parent_pid": parent_pid,
        "child_pid": child_pid,
        "child_start_time": child_start_time,
        "_host_hostname": "rd01",
    }


# ---- IngestReport basics ---------------------------------------------------


class TestIngestReport:
    def test_construction(self) -> None:
        now = datetime.now(timezone.utc)
        r = IngestReport(
            parser_name="Test",
            started_at=now,
            finished_at=now,
        )
        assert r.nodes_added == 0
        assert r.duration_seconds == 0.0

    def test_duration_seconds(self) -> None:
        start = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2023, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        r = IngestReport(parser_name="X", started_at=start, finished_at=end)
        assert r.duration_seconds == 5.0

    def test_repr_shows_counts(self) -> None:
        now = datetime.now(timezone.utc)
        r = IngestReport(
            parser_name="Defender",
            nodes_added=7,
            edges_added=0,
            started_at=now,
            finished_at=now,
        )
        repr_str = repr(r)
        assert "Defender" in repr_str
        assert "nodes=7" in repr_str


# ---- Orchestrator wired to Defender ----------------------------------------


class TestOrchestratorWithDefender:
    def test_run_defender_no_source_path(self, tmp_path: Path) -> None:
        """Orchestrator runs Defender parser without a file path (synthetic input)."""
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        parser = DefenderEvtxParser(store)

        events = [_defender_event() for _ in range(3)]
        # Each event has unique threat_name to avoid canonical_key collision
        events[0]["time_created"] = "2023-01-25T15:00:00+00:00"
        events[1]["time_created"] = "2023-01-25T15:01:00+00:00"
        events[2]["time_created"] = "2023-01-25T15:02:00+00:00"

        report = orch.run(parser, parse_input=events)
        assert report.nodes_added == 3
        assert report.nodes_merged == 0
        assert report.evidence_hash is None  # no source_path provided
        assert graph.node_count() == 3

    def test_run_defender_with_source_path_hashes_and_stores(self, tmp_path: Path) -> None:
        """Orchestrator hashes the source file and injects the hash into events."""
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        parser = DefenderEvtxParser(store)

        # Write a synthetic source file
        source = tmp_path / "Defender.evtx"
        source.write_bytes(b"binary evtx content, would be parsed in Day 5")
        expected_hash = hash_file(source)

        events = [_defender_event()]
        report = orch.run(parser, source_path=source, parse_input=events)

        # Hash flowed through
        assert report.evidence_hash == expected_hash
        # Node's evidence_hash matches
        nodes = list(graph.find_nodes(node_type="AntivirusDetection"))
        assert len(nodes) == 1
        assert nodes[0].evidence_hash == expected_hash
        # File was actually stored
        assert store.has(expected_hash)

    def test_run_carries_parser_stats(self, tmp_path: Path) -> None:
        """Defender parser's skipped_event_count flows into the report."""
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        parser = DefenderEvtxParser(store)

        events = [
            _defender_event(event_id=1117),       # supported
            _defender_event(event_id=1000),       # NOT supported
            _defender_event(event_id=1000),       # NOT supported (dup)
        ]
        report = orch.run(parser, parse_input=events)
        assert report.nodes_added == 1
        # Parser stats captured
        assert report.parser_stats["skipped_event_count"] == 2
        assert 1000 in report.parser_stats["skipped_event_ids"]

    def test_running_same_evidence_twice_merges(self, tmp_path: Path) -> None:
        """Idempotency: running twice with same input doesn't duplicate."""
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        parser = DefenderEvtxParser(store)

        events = [_defender_event()]
        r1 = orch.run(parser, parse_input=events)
        r2 = orch.run(parser, parse_input=events)

        assert r1.nodes_added == 1
        assert r2.nodes_added == 0     # second run merged
        assert r2.nodes_merged == 1
        assert graph.node_count() == 1


# ---- Orchestrator wired to Volatility --------------------------------------


class TestOrchestratorWithVolatility:
    def test_full_pipeline_produces_processes_and_spawned(self, tmp_path: Path) -> None:
        """End-to-end: synthetic memory dump 'file' + Volatility-shape input
        -> Process nodes + Spawned edge in the graph."""
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        parser = VolatilityProcessParser(store)

        memory_file = tmp_path / "rd01-memory.img"
        memory_file.write_bytes(b"synthetic memory contents for hashing")

        volatility_input = {
            "psscan": [
                _proc(pid=1244, name="svchost.exe", start_time="2023-01-25T08:00:00+00:00"),
                _proc(pid=1912, name="STUN.exe", parent_pid=1244,
                      start_time="2023-01-25T14:52:04+00:00"),
            ],
            "pslist": [
                _proc(pid=1244, name="svchost.exe", start_time="2023-01-25T08:00:00+00:00"),
                _proc(pid=1912, name="STUN.exe", parent_pid=1244,
                      start_time="2023-01-25T14:52:04+00:00"),
            ],
            "pstree": [
                _pstree(parent_pid=1244, child_pid=1912,
                        child_start_time="2023-01-25T14:52:04+00:00"),
            ],
        }
        report = orch.run(parser, source_path=memory_file, parse_input=volatility_input)

        assert report.nodes_added == 2
        assert report.edges_added == 1
        assert graph.node_count() == 2
        assert graph.edge_count() == 1

        # Both processes carry the memory dump's hash
        expected_hash = hash_file(memory_file)
        for n in graph.find_nodes(node_type="Process"):
            assert n.evidence_hash == expected_hash


# ---- Multi-parser pipeline (end-to-end) ------------------------------------


class TestMultiParserPipeline:
    def test_defender_then_volatility_share_one_graph(self, tmp_path: Path) -> None:
        """Run two different parsers against the same orchestrator/graph.
        Both contribute to one consistent graph state."""
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)

        # Defender run
        defender = DefenderEvtxParser(store)
        defender_file = tmp_path / "Defender.evtx"
        defender_file.write_bytes(b"defender evtx bytes")
        orch.run(
            defender,
            source_path=defender_file,
            parse_input=[_defender_event()],
        )

        # Volatility run
        vol_parser = VolatilityProcessParser(store)
        memory_file = tmp_path / "memory.img"
        memory_file.write_bytes(b"memory bytes")
        orch.run(
            vol_parser,
            source_path=memory_file,
            parse_input={
                "psscan": [
                    _proc(pid=1912, name="STUN.exe",
                          start_time="2023-01-25T14:52:04+00:00"),
                ],
            },
        )

        # Two different node types in the graph
        av_count = sum(1 for _ in graph.find_nodes(node_type="AntivirusDetection"))
        proc_count = sum(1 for _ in graph.find_nodes(node_type="Process"))
        assert av_count == 1
        assert proc_count == 1
        # Two reports
        assert len(orch.reports) == 2
        # Store has two evidence files
        assert len(store) == 2


# ---- Summary ----------------------------------------------------------------


class TestSummary:
    def test_empty_orchestrator_summary(self, tmp_path: Path) -> None:
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        assert orch.summary() == "No runs."

    def test_summary_after_runs(self, tmp_path: Path) -> None:
        graph = EvidenceGraph()
        store = EvidenceStore(tmp_path / "store")
        orch = Orchestrator(graph, store)
        parser = DefenderEvtxParser(store)
        orch.run(parser, parse_input=[_defender_event()])
        s = orch.summary()
        assert "1 run" in s
        assert "1 nodes" in s or "node" in s
