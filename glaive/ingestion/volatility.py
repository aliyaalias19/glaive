"""Parser for Volatility 3 process-related plugins.

Combines outputs from psscan, pslist, and pstree into a single coherent set
of Process nodes and Spawned edges.

For Day 4 (P2 decision): accepts pre-parsed plugin output as Python dicts.
Day 5 will add the thin layer that shells out to vol.py and parses its output.

Decisions:
  P4 — One parser handles 3 plugins (observed_by accumulates naturally)
  P5 — Process dict schema with _-prefixed orchestrator fields
  P6 — Uses schema's own merge_into() for cross-plugin merging
  P7 — pstree parent lookup uses wildcard-on-start_time + 'most recent before child'
  P8 — Spawned edges carry confirmed_by=['pstree'] (plus EVTX_4688 future)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from glaive.graph.edges import Spawned
from glaive.graph.nodes import Process
from glaive.ingestion.base import Parser, ParseResult


# Sort key for processes with no known start time
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class VolatilityProcessParseResult(ParseResult):
    """ParseResult with parser-specific stats."""

    processes_from_psscan: int = 0
    processes_from_pslist: int = 0
    spawn_edges_from_pstree: int = 0
    pstree_parent_lookup_failures: int = 0


class VolatilityProcessParser(Parser):
    """Builds Process nodes and Spawned edges from Volatility 3 plugin output.

    Input format (P5):
        parser.parse({
            "psscan":  [process_dict, ...],   # optional
            "pslist":  [process_dict, ...],   # optional
            "pstree":  [pstree_relation, ...] # optional, requires nodes built first
        })

    Each process_dict has keys:
        pid, name, image_path, command_line, parent_pid,
        start_time (ISO 8601 UTC), exit_time,
        _evidence_hash, _derivation, _host_hostname

    Each pstree_relation has:
        parent_pid, child_pid, child_start_time (ISO 8601 UTC),
        _evidence_hash, _derivation, _host_hostname
    """

    source_type = "Volatility process plugins"

    def parse(self, source: Any) -> VolatilityProcessParseResult:
        if isinstance(source, (str, Path)):
            raise NotImplementedError(
                "Binary Volatility execution is a Day 5 task. "
                "Pass a dict mapping plugin name -> list of dicts for now."
            )

        if not isinstance(source, dict):
            raise TypeError(
                f"VolatilityProcessParser expects a dict of plugin outputs, got {type(source).__name__}"
            )

        result = VolatilityProcessParseResult()

        # nodes_by_key: collects Process nodes by canonical_key for in-parse merging
        nodes_by_key: dict[tuple, Process] = {}

        # Pass 1: psscan
        for proc_dict in source.get("psscan", []):
            node = self._build_process(proc_dict, source_plugin="psscan")
            if node is None:
                continue
            key = node.canonical_key()
            if key in nodes_by_key:
                nodes_by_key[key].merge_into(node)
            else:
                nodes_by_key[key] = node
                result.processes_from_psscan += 1

        # Pass 2: pslist (merges with existing psscan entries via observed_by)
        for proc_dict in source.get("pslist", []):
            node = self._build_process(proc_dict, source_plugin="pslist")
            if node is None:
                continue
            key = node.canonical_key()
            if key in nodes_by_key:
                nodes_by_key[key].merge_into(node)
            else:
                nodes_by_key[key] = node
                result.processes_from_pslist += 1

        result.nodes = list(nodes_by_key.values())

        # Pass 3: pstree -> Spawned edges (only if both endpoints exist)
        for relation in source.get("pstree", []):
            edge = self._build_spawned(relation, nodes_by_key)
            if edge is None:
                result.pstree_parent_lookup_failures += 1
                continue
            result.edges.append(edge)
            result.spawn_edges_from_pstree += 1

        return result

    # ---- helpers ----

    def _build_process(self, proc_dict: dict, source_plugin: str) -> Process | None:
        """Build one Process node from a parsed plugin dict. Returns None if malformed."""
        try:
            start_time = self._parse_iso_utc_or_none(proc_dict.get("start_time"))
            exit_time = self._parse_iso_utc_or_none(proc_dict.get("exit_time"))
            return Process(
                evidence_hash=proc_dict["_evidence_hash"],
                derivation=proc_dict["_derivation"],
                host_hostname=proc_dict["_host_hostname"],
                pid=proc_dict["pid"],
                name=proc_dict["name"],
                image_path=proc_dict.get("image_path"),
                command_line=proc_dict.get("command_line"),
                parent_pid=proc_dict.get("parent_pid"),
                start_time=start_time,
                exit_time=exit_time,
                observed_by=[source_plugin],
            )
        except (KeyError, ValueError, TypeError):
            return None

    def _build_spawned(
        self, relation: dict, nodes_by_key: dict[tuple, Process]
    ) -> Spawned | None:
        """Build a Spawned edge from a pstree relation dict.

        Returns None if either endpoint can't be resolved (P7 — wildcard parent lookup).
        """
        try:
            host = relation["_host_hostname"]
            parent_pid = relation["parent_pid"]
            child_pid = relation["child_pid"]
            child_start_time = self._parse_iso_utc_or_none(relation.get("child_start_time"))
        except (KeyError, ValueError):
            return None

        # Look up child by exact key
        child_key = ("Process", host, child_pid, child_start_time)
        child = nodes_by_key.get(child_key)
        if child is None:
            return None

        # Look up parent by wildcard on start_time (P7)
        parent = self._find_parent(host, parent_pid, child_start_time, nodes_by_key)
        if parent is None:
            return None

        # Provenance: the relation's own hash, else the child's (both came from
        # the same memory image). Never a placeholder hash like "000...0".
        return Spawned(
            evidence_hash=relation.get("_evidence_hash") or child.evidence_hash,
            derivation=relation.get("_derivation") or child.derivation,
            source_key=parent.canonical_key(),
            target_key=child.canonical_key(),
            timestamp=child_start_time,
            confirmed_by=["pstree"],
        )

    def _find_parent(
        self,
        host: str,
        parent_pid: int,
        child_start_time: datetime | None,
        nodes_by_key: dict[tuple, Process],
    ) -> Process | None:
        """P7: find the Process with this PID on this host that most likely
        spawned a child at child_start_time.

        Heuristic: take the most recent parent process with start_time <= child_start_time.
        If child_start_time is None, take the most recent parent process overall.
        """
        candidates = [
            n for n in nodes_by_key.values()
            if n.host_hostname == host and n.pid == parent_pid
        ]
        if not candidates:
            return None

        def sort_key(p: Process) -> tuple[int, datetime]:
            # Known start times rank above unknown ones. Every datetime here is
            # tz-aware UTC, so we never compare naive with aware (v0.1 crashed
            # with TypeError when candidates mixed known and unknown times).
            if p.start_time is None:
                return (0, _EPOCH)
            return (1, p.start_time)

        if child_start_time is None:
            return max(candidates, key=sort_key)

        # Restrict to candidates that started before the child
        valid = [
            p for p in candidates
            if p.start_time is None or p.start_time <= child_start_time
        ]
        if not valid:
            return None

        # Among valid candidates, take the most recent
        return max(valid, key=sort_key)

    def _parse_iso_utc_or_none(self, ts_str: str | None) -> datetime | None:
        """Parse ISO 8601 string to tz-aware UTC datetime, or None for None/empty.
        Naive timestamps are assumed to be UTC."""
        if ts_str is None or ts_str == "":
            return None
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)