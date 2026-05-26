"""Tests for the Windows Defender EVTX parser.

Covers:
  - Supported event IDs (1116/1117/1118/1119/5001) produce AntivirusDetection nodes
  - Unsupported event IDs are skipped (counted, not raised)
  - Malformed events are skipped, parsing continues
  - The SRL scenario: msedge.exe Defender detections produce the expected node count
  - Binary file path raises NotImplementedError (Day 5 contract)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.evidence.store import EvidenceStore
from glaive.graph.nodes import AntivirusDetection
from glaive.ingestion.defender import DefenderEvtxParser, SUPPORTED_EVENT_IDS


VALID_HASH = "a" * 64


def _make_event(
    event_id: int,
    time_created: str = "2023-01-25T15:00:00+00:00",
    threat_name: str = "Trojan:Win32/PowerRunner.A",
    action: str = "Quarantined",
    file_path: str = "C:\\Users\\rsydow\\AppData\\Local\\Temp\\msedge.exe",
    computer: str = "rd01",
) -> dict:
    """Helper to build a minimal Defender event dict."""
    return {
        "event_id": event_id,
        "time_created": time_created,
        "computer": computer,
        "threat_name": threat_name,
        "action": action,
        "file_path": file_path,
        "_evidence_hash": VALID_HASH,
        "_derivation": "Defender EVTX test fixture",
    }


# ---- Supported event IDs --------------------------------------------------


class TestSupportedEventIds:
    def test_all_five_supported_ids_produce_nodes(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        events = [_make_event(eid) for eid in [1116, 1117, 1118, 1119, 5001]]
        result = parser.parse(events)
        assert len(result.nodes) == 5
        assert result.skipped_event_count == 0

    def test_node_fields_extracted_correctly(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        events = [
            _make_event(
                event_id=1117,
                time_created="2023-01-25T15:00:00+00:00",
                threat_name="Trojan:Win32/PowerRunner.A",
                action="Quarantined",
                file_path="C:\\Users\\rsydow\\AppData\\Local\\Temp\\msedge.exe",
            )
        ]
        result = parser.parse(events)
        n = result.nodes[0]
        assert isinstance(n, AntivirusDetection)
        assert n.event_id == 1117
        assert n.threat_name == "Trojan:Win32/PowerRunner.A"
        assert n.action_taken == "Quarantined"
        assert n.file_path == "C:\\Users\\rsydow\\AppData\\Local\\Temp\\msedge.exe"
        assert n.host_hostname == "rd01"
        assert n.detection_time == datetime(2023, 1, 25, 15, 0, 0, tzinfo=timezone.utc)

    def test_evidence_hash_carried_through(self, tmp_path: Path) -> None:
        """The _evidence_hash field on input dicts ends up on the node."""
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        custom_hash = "b" * 64
        event = _make_event(1117)
        event["_evidence_hash"] = custom_hash
        result = parser.parse([event])
        assert result.nodes[0].evidence_hash == custom_hash


# ---- Skip semantics -------------------------------------------------------


class TestSkipSemantics:
    def test_unsupported_event_id_is_skipped(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        # 1000 is a normal Defender startup event, not in SUPPORTED_EVENT_IDS
        events = [_make_event(1000), _make_event(1117)]
        result = parser.parse(events)
        assert len(result.nodes) == 1
        assert result.skipped_event_count == 1
        assert 1000 in result.skipped_event_ids

    def test_skipped_event_ids_deduplicated(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        events = [_make_event(1000), _make_event(1000), _make_event(1000)]
        result = parser.parse(events)
        assert result.skipped_event_count == 3
        # 1000 appears once in the deduplicated list
        assert result.skipped_event_ids == [1000]

    def test_malformed_event_skipped_silently(self, tmp_path: Path) -> None:
        """An event dict missing required fields is dropped, others continue."""
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        good = _make_event(1117)
        bad = {"event_id": 1117}  # missing time_created, computer, etc.
        result = parser.parse([bad, good])
        # The bad one was skipped — only the good produced a node
        assert len(result.nodes) == 1

    def test_empty_input_returns_empty_result(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        result = parser.parse([])
        assert len(result.nodes) == 0
        assert result.skipped_event_count == 0


# ---- The SRL msedge.exe scenario ------------------------------------------


class TestSrlScenario:
    """The schema-promised use case from the SRL ground truth:
    Defender repeatedly detects and quarantines msedge.exe instances.
    """

    def test_seven_msedge_detections_produce_seven_nodes(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        # Seven distinct detections, each at a unique time (per schema 2.10
        # identity = host + event_id + time + threat_name)
        events = [
            _make_event(
                event_id=1117,
                time_created=f"2023-01-25T15:0{i}:00+00:00",
                threat_name="Trojan:Win32/PowerRunner.A",
            )
            for i in range(7)
        ]
        result = parser.parse(events)
        assert len(result.nodes) == 7
        # All seven canonical_keys are distinct
        keys = {n.canonical_key() for n in result.nodes}
        assert len(keys) == 7

    def test_repeated_threat_same_time_dedups_at_graph_level(self, tmp_path: Path) -> None:
        """Two ingestions of the same event produce two nodes with identical
        canonical_keys. When added to a graph, they merge — but the parser
        itself produces both."""
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        same_event = _make_event(1117)
        result = parser.parse([same_event, same_event])
        # The parser returns both; merging happens in the graph wrapper
        assert len(result.nodes) == 2
        # But they have identical canonical_keys
        assert result.nodes[0].canonical_key() == result.nodes[1].canonical_key()


# ---- Binary EVTX path ------------------------------------------------------


class TestBinaryEvtxNotYetSupported:
    def test_path_input_raises_not_implemented(self, tmp_path: Path) -> None:
        """Passing a Path (binary EVTX) raises — Day 5 will implement this."""
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        with pytest.raises(NotImplementedError, match="Day 5"):
            parser.parse(Path("/fake/Defender.evtx"))

    def test_string_path_input_also_raises(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = DefenderEvtxParser(store)
        with pytest.raises(NotImplementedError):
            parser.parse("/fake/Defender.evtx")


# ---- Supported event IDs constant ------------------------------------------


def test_supported_event_ids_match_schema() -> None:
    """The constant matches schema section 2.10 — guards against schema drift."""
    assert SUPPORTED_EVENT_IDS == {1116, 1117, 1118, 1119, 5001}
