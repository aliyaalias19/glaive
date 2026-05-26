"""Tests for the Volatility 3 process parser.

Covers:
  - psscan alone produces Process nodes with observed_by=['psscan']
  - pslist alone produces Process nodes with observed_by=['pslist']
  - psscan + pslist on same process merges observed_by=['psscan', 'pslist']
  - Hidden process: psscan-only entry has observed_by=['psscan']
  - pstree produces Spawned edges between built Process nodes
  - Pstree lookup failures (missing parent) increment counter, don't crash
  - The SRL scenario: svchost (PID 1244) -> STUN (PID 1912) Spawned edge
  - Binary file path raises NotImplementedError
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.evidence.store import EvidenceStore
from glaive.graph.edges import Spawned
from glaive.graph.nodes import Process
from glaive.ingestion.volatility import VolatilityProcessParser


VALID_HASH = "a" * 64

# Sample timestamps
SVCHOST_START = "2023-01-25T08:00:00+00:00"
STUN_START = "2023-01-25T14:52:04+00:00"


def _proc(
    pid: int,
    name: str,
    *,
    image_path: str | None = None,
    parent_pid: int | None = None,
    start_time: str | None = None,
    host: str = "rd01",
    derivation: str = "vol windows.X rd01-memory.img",
) -> dict:
    """Build a process dict for parser input."""
    return {
        "pid": pid,
        "name": name,
        "image_path": image_path,
        "command_line": None,
        "parent_pid": parent_pid,
        "start_time": start_time,
        "exit_time": None,
        "_evidence_hash": VALID_HASH,
        "_derivation": derivation,
        "_host_hostname": host,
    }


def _pstree(
    parent_pid: int, child_pid: int, child_start_time: str | None, *, host: str = "rd01"
) -> dict:
    return {
        "parent_pid": parent_pid,
        "child_pid": child_pid,
        "child_start_time": child_start_time,
        "_evidence_hash": VALID_HASH,
        "_derivation": "vol windows.pstree rd01-memory.img",
        "_host_hostname": host,
    }


# ---- Single plugin inputs --------------------------------------------------


class TestSinglePluginInputs:
    def test_psscan_only_produces_observed_by_psscan(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "psscan": [_proc(pid=1912, name="STUN.exe", start_time=STUN_START)]
        })
        assert len(result.nodes) == 1
        assert result.nodes[0].observed_by == ["psscan"]
        assert result.processes_from_psscan == 1
        assert result.processes_from_pslist == 0

    def test_pslist_only_produces_observed_by_pslist(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "pslist": [_proc(pid=1912, name="STUN.exe", start_time=STUN_START)]
        })
        assert len(result.nodes) == 1
        assert result.nodes[0].observed_by == ["pslist"]

    def test_empty_input_returns_empty_result(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({})
        assert len(result.nodes) == 0
        assert len(result.edges) == 0


# ---- Cross-plugin merge (observed_by accumulation) --------------------------


class TestCrossPluginMerge:
    def test_same_process_in_psscan_and_pslist_merges(self, tmp_path: Path) -> None:
        """The schema's observed_by pattern in action: one node, two sources."""
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        proc = _proc(pid=1912, name="STUN.exe", start_time=STUN_START)
        result = parser.parse({"psscan": [proc], "pslist": [proc]})
        # One node, both plugins in observed_by
        assert len(result.nodes) == 1
        assert sorted(result.nodes[0].observed_by) == sorted(["psscan", "pslist"])

    def test_hidden_process_only_in_psscan(self, tmp_path: Path) -> None:
        """The canonical 'hidden process' pattern: psscan sees it, pslist doesn't."""
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "psscan": [_proc(pid=9999, name="hidden.exe", start_time=STUN_START)],
            "pslist": [_proc(pid=1912, name="STUN.exe", start_time=STUN_START)],
        })
        # Two distinct processes
        assert len(result.nodes) == 2
        hidden = next(n for n in result.nodes if n.pid == 9999)
        visible = next(n for n in result.nodes if n.pid == 1912)
        assert hidden.observed_by == ["psscan"]
        assert "pslist" not in hidden.observed_by
        assert "psscan" not in visible.observed_by

    def test_process_attribute_filled_from_first_seeing_plugin(self, tmp_path: Path) -> None:
        """psscan has command_line, pslist doesn't -> merged node has it."""
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        p_full = _proc(pid=1912, name="STUN.exe", start_time=STUN_START)
        p_full["command_line"] = "STUN.exe --daemon"
        p_empty = _proc(pid=1912, name="STUN.exe", start_time=STUN_START)
        # pslist sees the process but doesn't carry command_line in our fixture
        result = parser.parse({"psscan": [p_full], "pslist": [p_empty]})
        assert len(result.nodes) == 1
        assert result.nodes[0].command_line == "STUN.exe --daemon"


# ---- Spawned edges from pstree --------------------------------------------


class TestSpawnedFromPstree:
    def test_pstree_produces_spawned_edge(self, tmp_path: Path) -> None:
        """The SRL canonical case: svchost (1244) -> STUN (1912)."""
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "psscan": [
                _proc(pid=1244, name="svchost.exe", start_time=SVCHOST_START),
                _proc(pid=1912, name="STUN.exe", parent_pid=1244, start_time=STUN_START),
            ],
            "pstree": [
                _pstree(parent_pid=1244, child_pid=1912, child_start_time=STUN_START),
            ],
        })
        assert len(result.nodes) == 2
        assert len(result.edges) == 1
        edge = result.edges[0]
        assert isinstance(edge, Spawned)
        assert edge.source_key[2] == 1244  # canonical_key is ('Process', host, pid, start_time)
        assert edge.target_key[2] == 1912
        assert edge.confirmed_by == ["pstree"]
        assert edge.confidence == "suspected"  # one source

    def test_pstree_missing_parent_increments_failure(self, tmp_path: Path) -> None:
        """pstree references PID 99999 but no such Process node exists."""
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "psscan": [_proc(pid=1912, name="STUN.exe", start_time=STUN_START)],
            "pstree": [
                _pstree(parent_pid=99999, child_pid=1912, child_start_time=STUN_START),
            ],
        })
        # The child exists but the parent doesn't -> edge skipped
        assert len(result.edges) == 0
        assert result.pstree_parent_lookup_failures == 1

    def test_pstree_missing_child_also_increments_failure(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "psscan": [_proc(pid=1244, name="svchost.exe", start_time=SVCHOST_START)],
            "pstree": [
                _pstree(parent_pid=1244, child_pid=1912, child_start_time=STUN_START),
            ],
        })
        # The parent exists but child doesn't -> edge skipped
        assert len(result.edges) == 0
        assert result.pstree_parent_lookup_failures == 1


# ---- The SRL STUN.exe pipeline end-to-end ---------------------------------


class TestSrlStunPipeline:
    """The canonical SRL finding from the parser's perspective:
    psscan + pslist + pstree -> Process(svchost, observed=[psscan,pslist])
                              + Process(STUN, observed=[psscan,pslist])
                              + Spawned(svchost -> STUN, confirmed_by=[pstree])
    """

    def test_full_pipeline(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        result = parser.parse({
            "psscan": [
                _proc(pid=1244, name="svchost.exe", start_time=SVCHOST_START),
                _proc(pid=1912, name="STUN.exe", parent_pid=1244, start_time=STUN_START),
            ],
            "pslist": [
                _proc(pid=1244, name="svchost.exe", start_time=SVCHOST_START),
                _proc(pid=1912, name="STUN.exe", parent_pid=1244, start_time=STUN_START),
            ],
            "pstree": [
                _pstree(parent_pid=1244, child_pid=1912, child_start_time=STUN_START),
            ],
        })

        # Two nodes, both with both observation sources
        assert len(result.nodes) == 2
        for n in result.nodes:
            assert sorted(n.observed_by) == sorted(["psscan", "pslist"])

        # One Spawned edge
        assert len(result.edges) == 1


# ---- Binary path contract --------------------------------------------------


class TestBinaryNotYetSupported:
    def test_path_input_raises_not_implemented(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        with pytest.raises(NotImplementedError, match="Day 5"):
            parser.parse(Path("/fake/memory.img"))

    def test_wrong_type_raises_type_error(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        parser = VolatilityProcessParser(store)
        with pytest.raises(TypeError, match="dict"):
            parser.parse([{"event_id": 1117}])  # type: ignore[arg-type]
