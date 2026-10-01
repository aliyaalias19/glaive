"""v0.2 regressions: no fabricated evidence hashes, tamper events kept,
and two ingestion crashes fixed."""
from __future__ import annotations

from pathlib import Path

from glaive.evidence.store import EvidenceStore
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.defender import DefenderEvtxParser
from glaive.ingestion.orchestrator import Orchestrator
from glaive.ingestion.volatility import VolatilityProcessParser

H = "a" * 64


def _event(**overrides) -> dict:
    ev = {"event_id": 1116, "time_created": "2025-04-12T08:00:00+00:00",
          "computer": "h1", "threat_name": "Trojan:Win32/X", "_evidence_hash": H}
    ev.update(overrides)
    return ev


# ---- Defender ----------------------------------------------------------------


def test_real_time_protection_disabled_is_kept(tmp_path: Path) -> None:
    """v0.1 silently dropped event 5001 because it has no threat name."""
    parser = DefenderEvtxParser(EvidenceStore(tmp_path / "s"))
    result = parser.parse([_event(event_id=5001, threat_name=None)])
    assert len(result.nodes) == 1
    assert result.nodes[0].event_description == "Real-time protection disabled"
    assert result.tamper_events == 1


def test_detection_without_threat_name_is_malformed(tmp_path: Path) -> None:
    parser = DefenderEvtxParser(EvidenceStore(tmp_path / "s"))
    result = parser.parse([_event(threat_name=None)])
    assert result.nodes == []
    assert result.skipped_malformed == 1


def test_no_evidence_hash_means_rejected_not_faked(tmp_path: Path) -> None:
    """v0.1 stamped such records with evidence_hash='fff...f'."""
    parser = DefenderEvtxParser(EvidenceStore(tmp_path / "s"))
    ev = _event()
    del ev["_evidence_hash"]
    result = parser.parse([ev])
    assert result.nodes == []
    assert result.skipped_missing_provenance == 1


def test_extra_detail_is_read_from_raw_data(tmp_path: Path) -> None:
    parser = DefenderEvtxParser(EvidenceStore(tmp_path / "s"))
    raw = {"Severity Name": "Severe", "Process Name": "C:\\x.exe", "Detection User": "CORP\\bob"}
    node = parser.parse([_event(raw_data=raw)]).nodes[0]
    assert (node.severity, node.process_name, node.detection_user) == (
        "Severe", "C:\\x.exe", "CORP\\bob")


# ---- Orchestrator --------------------------------------------------------------


def test_run_without_path_then_with_path_does_not_crash(tmp_path: Path) -> None:
    """v0.1 read the PREVIOUS run's source_path and raised TypeError when it was None."""
    store = EvidenceStore(tmp_path / "s")
    orch = Orchestrator(EvidenceGraph(), store)
    orch.run(DefenderEvtxParser(store), parse_input=[_event()])

    source = tmp_path / "Defender.evtx"
    source.write_bytes(b"x")
    ev = _event(time_created="2025-04-12T09:00:00+00:00")
    del ev["_evidence_hash"]
    report = orch.run(DefenderEvtxParser(store), source_path=source, parse_input=[ev])

    assert report.nodes_added == 1
    node = next(orch.graph.find_nodes("AntivirusDetection",
                                      lambda n: n.evidence_hash == report.evidence_hash))
    assert node.derivation == "Defender EVTX Defender.evtx"


# ---- Volatility ----------------------------------------------------------------


def test_pstree_with_unknown_start_times_does_not_crash(tmp_path: Path) -> None:
    """v0.1 compared naive and timezone-aware datetimes and raised TypeError."""
    parser = VolatilityProcessParser(EvidenceStore(tmp_path / "s"))
    base = {"_evidence_hash": H, "_derivation": "vol", "_host_hostname": "h"}
    source = {
        "psscan": [
            {**base, "pid": 4, "name": "System", "start_time": "2025-01-01T00:00:00+00:00"},
            {**base, "pid": 4, "name": "System", "start_time": None},
            {**base, "pid": 8, "name": "child", "start_time": None},
        ],
        "pstree": [{"parent_pid": 4, "child_pid": 8, "child_start_time": None,
                    "_host_hostname": "h"}],
    }
    result = parser.parse(source)
    assert len(result.edges) == 1


def test_spawned_edge_inherits_real_hash(tmp_path: Path) -> None:
    """v0.1 gave Spawned edges evidence_hash='000...0' when the relation had none."""
    parser = VolatilityProcessParser(EvidenceStore(tmp_path / "s"))
    base = {"_evidence_hash": H, "_derivation": "vol", "_host_hostname": "h"}
    source = {
        "psscan": [
            {**base, "pid": 4, "name": "System", "start_time": "2025-01-01T00:00:00+00:00"},
            {**base, "pid": 8, "name": "child", "start_time": "2025-01-01T00:01:00+00:00"},
        ],
        "pstree": [{"parent_pid": 4, "child_pid": 8,
                    "child_start_time": "2025-01-01T00:01:00+00:00", "_host_hostname": "h"}],
    }
    edge = parser.parse(source).edges[0]
    assert edge.evidence_hash == H
    assert edge.derivation == "vol"