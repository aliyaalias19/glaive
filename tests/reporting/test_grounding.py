"""Tests for claim grounding: the gate must check WHAT a claim says,
not only that its cited nodes exist."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.edges import Spawned
from glaive.graph.nodes import AntivirusDetection, Process
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.tools import do_commit_finding, do_query_graph
from glaive.reporting.grounding import extract_entities

H = "a" * 64
T0 = datetime(2025, 4, 12, 8, 21, 44, tzinfo=timezone.utc)


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    s = GlaiveSession(analysis_dir=tmp_path)
    s.graph.add_node(AntivirusDetection(
        evidence_hash=H, derivation="test", host_hostname="h1", event_id=1116,
        threat_name="Trojan:Win32/Cloxer", file_path="C:\\Users\\bob\\cloxer.exe",
        detection_time=T0))
    return s


def _av_key(s: GlaiveSession) -> list:
    return do_query_graph(s, "AntivirusDetection")["nodes"][0]["canonical_key"]


# ---- entity extraction -------------------------------------------------------


def test_extracts_common_forensic_entities() -> None:
    kinds = {e.kind: e.value for e in extract_entities(
        "Trojan:Win32/Cloxer ran from C:\\Temp\\a.exe and called 10.0.0.5 on port 4444")}
    assert kinds["threat_name"] == "Trojan:Win32/Cloxer"
    assert kinds["windows_path"] == "C:\\Temp\\a.exe"
    assert kinds["ip"] == "10.0.0.5"
    assert kinds["port"] == "4444"


def test_plain_sentence_has_no_entities() -> None:
    assert extract_entities("Defender detected a Trojan") == []


# ---- the gate ----------------------------------------------------------------


def test_claim_with_invented_ip_is_rejected(session: GlaiveSession) -> None:
    """The exact v0.1 hole: a real node cited for an unrelated claim."""
    r = do_commit_finding(
        session, "Domain admin credentials were exfiltrated to 8.8.8.8",
        [_av_key(session)], "inferred")
    assert r["decision"] == "rejected_ungrounded_claim"
    assert r["committed"] is False
    assert "ip:8.8.8.8" in r["grounding"]["ungrounded"]
    assert session.report.findings == []


def test_claim_matching_evidence_is_accepted(session: GlaiveSession) -> None:
    r = do_commit_finding(
        session, "Defender detected Trojan:Win32/Cloxer in C:\\Users\\bob\\cloxer.exe",
        [_av_key(session)], "inferred")
    assert r["committed"] is True
    assert r["grounding"]["coverage"] == 1.0


def test_matching_ignores_case_and_slash_direction(session: GlaiveSession) -> None:
    r = do_commit_finding(session, "Found trojan:win32/cloxer at c:/users/bob/CLOXER.EXE",
                          [_av_key(session)], "inferred")
    assert r["committed"] is True


def test_entity_found_one_hop_away_counts(tmp_path: Path) -> None:
    """Citing the parent process grounds a claim naming its child (via Spawned)."""
    s = GlaiveSession(analysis_dir=tmp_path)
    parent = s.graph.add_node(Process(evidence_hash=H, derivation="t", host_hostname="h",
                                      pid=4, name="svchost.exe", start_time=T0))
    child = s.graph.add_node(Process(evidence_hash=H, derivation="t", host_hostname="h",
                                     pid=8, name="STUN.exe", start_time=T0))
    s.graph.add_edge(Spawned(evidence_hash=H, derivation="t", source_key=parent.canonical_key(),
                             target_key=child.canonical_key(), confirmed_by=["pstree"]))
    key = do_query_graph(s, "Process", [{"field": "pid", "op": "eq", "value": 4}])
    r = do_commit_finding(s, "svchost.exe spawned STUN.exe",
                          [key["nodes"][0]["canonical_key"]], "suspected")
    assert r["committed"] is True


def test_one_invented_entity_among_real_ones_is_rejected(session: GlaiveSession) -> None:
    r = do_commit_finding(
        session, "Trojan:Win32/Cloxer in cloxer.exe beaconed to evil-c2.ru",
        [_av_key(session)], "inferred")
    assert r["decision"] == "rejected_ungrounded_claim"
    assert r["grounding"]["ungrounded"] == ["domain:evil-c2.ru"]
