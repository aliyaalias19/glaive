""".glaive case files and graph serialization."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from glaive.case import CaseFile, CaseFileError
from glaive.graph.edges import Spawned
from glaive.graph.nodes import AntivirusDetection, Process
from glaive.graph.wrapper import EvidenceGraph, decode_key, encode_key
from glaive.mcp_server import tools
from glaive.mcp_server.session import GlaiveSession

H = "a" * 64
T = datetime(2026, 9, 14, 9, 0, tzinfo=UTC)


def _graph() -> EvidenceGraph:
    g = EvidenceGraph()
    p = g.add_node(Process(evidence_hash=H, derivation="t", host_hostname="h", pid=4,
                           name="a.exe", start_time=T, observed_by=["sysmon_1"]))
    c = g.add_node(Process(evidence_hash=H, derivation="t", host_hostname="h", pid=8,
                           name="b.exe", start_time=None))
    g.add_edge(Spawned(evidence_hash=H, derivation="t", source_key=p.canonical_key(),
                       target_key=c.canonical_key(), timestamp=T, confirmed_by=["x", "y"]))
    g.add_node(AntivirusDetection(evidence_hash=H, derivation="t", host_hostname="h",
                                  event_id=5001, detection_time=T))
    return g


def test_key_codec_round_trip() -> None:
    key = ("Process", "h", 4, T, None, ("nested", 1))
    assert decode_key(encode_key(key)) == key


def test_graph_round_trip_is_lossless() -> None:
    g = _graph()
    g2 = EvidenceGraph.from_dict(g.to_dict())
    assert {n.canonical_key() for n in g2.find_nodes()} == {n.canonical_key() for n in g.find_nodes()}
    edge = next(g2.all_edges("Spawned"))
    assert edge.confidence == "confirmed"
    assert g2.to_dict() == g.to_dict()


def test_session_save_and_load(tmp_path: Path) -> None:
    s = GlaiveSession(analysis_dir=tmp_path, case_name="My case")
    s.graph = _graph()
    s.orchestrator.graph = s.graph
    key = tools.do_query_graph(s, "AntivirusDetection")["nodes"][0]["canonical_key"]
    r = tools.do_commit_finding(s, "Real-time protection was disabled on h", [key], "inferred",
                                severity="high", mitre_techniques=["T1562.001"])
    assert r["committed"]
    s.log("analyst", "note", text="hello")
    path = s.save()
    assert path.name == "case.glaive"

    s2 = GlaiveSession.load(tmp_path)
    assert s2.case_name == "My case"
    assert s2.graph.node_count() == s.graph.node_count()
    f = s2.report.findings[0]
    assert f.mitre_techniques == ["T1562.001"] and f.status == "pending_approval"
    assert [tuple(k) for k in f.supporting_node_keys] == [tuple(k) for k in
                                                          s.report.findings[0].supporting_node_keys]
    assert any(e["action"] == "note" for e in s2.audit_log)
    # findings on a reloaded case still pass the gate's node check
    assert s2.graph.has_node(tuple(f.supporting_node_keys[0]))


def test_saving_twice_appends_audit_once(tmp_path: Path) -> None:
    s = GlaiveSession(analysis_dir=tmp_path)
    s.log("a", "one")
    s.save()
    s.save()
    with CaseFile(tmp_path / "case.glaive") as cf:
        assert [e["action"] for e in cf.audit()] == ["one"]


def test_not_a_case_file(tmp_path: Path) -> None:
    bad = tmp_path / "case.glaive"
    bad.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(CaseFileError):
        CaseFile(bad)


def test_newer_schema_refused(tmp_path: Path) -> None:
    p = tmp_path / "case.glaive"
    CaseFile(p).close()
    con = sqlite3.connect(p)
    con.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    con.commit()
    con.close()
    with pytest.raises(CaseFileError, match="newer"):
        CaseFile(p)


def test_load_missing_case(tmp_path: Path) -> None:
    with pytest.raises(CaseFileError):
        GlaiveSession.load(tmp_path / "nothing")


def test_timeline_and_paths() -> None:
    g = _graph()
    tl = g.timeline()
    assert tl == sorted(tl, key=lambda r: r["time"])
    assert g.shortest_path(("Process", "h", 4, T), ("Process", "h", 8, None)) is not None
    assert g.type_counts() == {"AntivirusDetection": 1, "Process": 2}
