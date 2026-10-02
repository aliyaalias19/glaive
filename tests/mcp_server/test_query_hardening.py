"""v0.2 regressions for query_graph and key handling."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.nodes import AntivirusDetection, File
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.tools import (
    MAX_QUERY_LIMIT,
    do_commit_finding,
    do_get_node_provenance,
    do_query_graph,
)

H = "a" * 64
T0 = datetime(2025, 4, 12, 8, 21, 44, tzinfo=timezone.utc)


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    s = GlaiveSession(analysis_dir=tmp_path)
    for i in range(3):
        s.graph.add_node(AntivirusDetection(
            evidence_hash=H, derivation="t", host_hostname="h1", event_id=1116,
            threat_name=f"Trojan:Win32/T{i}", detection_time=T0.replace(day=10 + i)))
    return s


# ---- limits ------------------------------------------------------------------


def test_huge_limit_is_capped(tmp_path: Path) -> None:
    s = GlaiveSession(analysis_dir=tmp_path)
    for i in range(MAX_QUERY_LIMIT + 50):
        s.graph.add_node(AntivirusDetection(
            evidence_hash=H, derivation="t", host_hostname="h", event_id=1116,
            threat_name=f"T:W/{i}", detection_time=T0))
    r = do_query_graph(s, limit=99_999_999)
    assert r["returned"] == MAX_QUERY_LIMIT
    assert r["truncated"] is True


def test_negative_limit_returns_at_least_one(session: GlaiveSession) -> None:
    """v0.1: limit=-5 returned 0 nodes with truncated=True."""
    r = do_query_graph(session, limit=-5)
    assert r["returned"] == 1


# ---- filters -----------------------------------------------------------------


@pytest.mark.parametrize("field", ["__class__", "model_config", "__dict__", "canonical_key"])
def test_filters_cannot_probe_internals(session: GlaiveSession, field: str) -> None:
    r = do_query_graph(session, filters=[{"field": field, "op": "exists", "value": True}])
    assert r["error"] == "bad_filter_field"


def test_time_range_with_iso_strings(session: GlaiveSession) -> None:
    """v0.1 compared a string with a datetime and silently matched nothing."""
    r = do_query_graph(session, "AntivirusDetection", [
        {"field": "detection_time", "op": "gte", "value": "2025-04-11T00:00:00Z"},
        {"field": "detection_time", "op": "lt", "value": "2025-04-12T00:00:00Z"},
    ])
    assert r["total_matched"] == 1
    assert r["nodes"][0]["threat_name"] == "Trojan:Win32/T1"


def test_new_operators(session: GlaiveSession) -> None:
    def count(flt: dict) -> int:
        return do_query_graph(session, "AntivirusDetection", [flt])["total_matched"]

    assert count({"field": "threat_name", "op": "icontains", "value": "trojan"}) == 3
    assert count({"field": "threat_name", "op": "ne", "value": "Trojan:Win32/T0"}) == 2
    assert count({"field": "threat_name", "op": "in",
                  "value": ["Trojan:Win32/T0", "Trojan:Win32/T2"]}) == 2


# ---- summaries and keys ------------------------------------------------------


def test_file_results_include_the_path(tmp_path: Path) -> None:
    s = GlaiveSession(analysis_dir=tmp_path)
    s.graph.add_node(File(evidence_hash=H, derivation="t", host_hostname="h1",
                          full_path="C:\\evil.exe", on_disk=True))
    node = do_query_graph(s, "File")["nodes"][0]
    assert node["full_path"] == "C:\\evil.exe"
    assert node["on_disk"] is True


def test_date_like_hostname_still_resolves(tmp_path: Path) -> None:
    """v0.1 turned the hostname '20240101' into a datetime, so lookups failed."""
    s = GlaiveSession(analysis_dir=tmp_path)
    s.graph.add_node(File(evidence_hash=H, derivation="t", host_hostname="20240101",
                          full_path="C:\\x.exe"))
    key = do_query_graph(s, "File")["nodes"][0]["canonical_key"]
    assert do_get_node_provenance(s, key)["status"] == "ok"
    r = do_commit_finding(s, "x.exe was present", [key], "inferred")
    assert r["committed"] is True


def test_datetime_keys_still_round_trip(session: GlaiveSession) -> None:
    key = do_query_graph(session, "AntivirusDetection")["nodes"][0]["canonical_key"]
    assert isinstance(key[3], str)  # JSON form
    assert do_get_node_provenance(session, key)["status"] == "ok"
