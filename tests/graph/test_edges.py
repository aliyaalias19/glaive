"""Tests for the typed edge subclasses in glaive/graph/edges.py.

One test class per edge type. Tests verify:
  - canonical_key() includes edge_type (distinguishes from other types between same nodes)
  - confirmed_by + confidence patterns work end-to-end
  - merge_into() unions confirmed_by from multiple ingestions

Reference: docs/EVIDENCE_GRAPH_SCHEMA.md section 3.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from glaive.graph.edges import Connected, Deleted, Executed, Read, Spawned, Wrote


VALID_HASH = "a" * 64


# Convenience: canonical keys of two test Process nodes (no Process import needed for edges)
PROC_PARENT = ("Process", "rd01", 1244, None)
PROC_CHILD = ("Process", "rd01", 1912, None)


# =============================================================================
# Spawned
# =============================================================================


class TestSpawned:
    """Schema section 3.1 — Spawned edge (Process -> Process)."""

    def test_minimal_construction(self) -> None:
        e = Spawned(
            evidence_hash=VALID_HASH,
            derivation="vol windows.pstree",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
        )
        assert e.source_key == PROC_PARENT
        assert e.target_key == PROC_CHILD
        assert e.confirmed_by == []
        assert e.confidence == "inferred"

    def test_with_confirmed_by(self) -> None:
        ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        e = Spawned(
            evidence_hash=VALID_HASH,
            derivation="evtx_4688",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
            timestamp=ts,
            confirmed_by=["evtx_4688", "pstree"],
        )
        assert e.confidence == "confirmed"

    def test_canonical_key_includes_edge_type(self) -> None:
        """An edge's canonical key includes 'Spawned' to distinguish from
        other edge types between the same nodes."""
        ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        e = Spawned(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
            timestamp=ts,
        )
        key = e.canonical_key()
        assert key == (PROC_PARENT, PROC_CHILD, "Spawned", ts)

    def test_canonical_keys_distinguish_timestamps(self) -> None:
        """Two Spawned edges between same nodes at different times = distinct."""
        ts1 = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        ts2 = datetime(2023, 1, 25, 14, 53, 10, tzinfo=timezone.utc)
        e1 = Spawned(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
            timestamp=ts1,
        )
        e2 = Spawned(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
            timestamp=ts2,
        )
        assert e1.canonical_key() != e2.canonical_key()

    def test_merge_unions_confirmed_by(self) -> None:
        """Two Spawned edges representing the same event from different sources merge."""
        ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        e1 = Spawned(
            evidence_hash=VALID_HASH,
            derivation="vol windows.pstree",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
            timestamp=ts,
            confirmed_by=["pstree"],
        )
        e2 = Spawned(
            evidence_hash=VALID_HASH,
            derivation="evtx_4688",
            source_key=PROC_PARENT,
            target_key=PROC_CHILD,
            timestamp=ts,
            confirmed_by=["evtx_4688"],
        )
        e1.merge_into(e2)
        assert e1.confirmed_by == ["pstree", "evtx_4688"]
        assert e1.confidence == "confirmed"


# =============================================================================
# Executed
# =============================================================================


# Canonical keys of test source nodes
TASK_STUN = ("ScheduledTask", "rd01", "\\STUN")
PROC_STUN = ("Process", "rd01", 1912, None)
USER_RSYDOW = ("User", "S-1-5-21-1234567890-1234567890-1234567890-1001")


class TestExecuted:
    """Schema section 3.3 — Executed edge."""

    def test_minimal_construction(self) -> None:
        e = Executed(
            evidence_hash=VALID_HASH,
            derivation="task_xml",
            source_key=TASK_STUN,
            target_key=PROC_STUN,
        )
        assert e.command_line is None
        assert e.confidence == "inferred"

    def test_full_construction(self) -> None:
        ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        e = Executed(
            evidence_hash=VALID_HASH,
            derivation="evtx_4688",
            source_key=TASK_STUN,
            target_key=PROC_STUN,
            timestamp=ts,
            command_line="C:\\Windows\\System32\\STUN.exe --daemon",
            confirmed_by=["evtx_4688", "amcache", "prefetch"],
        )
        assert e.command_line == "C:\\Windows\\System32\\STUN.exe --daemon"
        assert e.confidence == "confirmed"

    def test_canonical_key_distinguishes_from_spawned(self) -> None:
        """An Executed edge and a Spawned edge between the same nodes/timestamp are distinct."""
        ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        executed = Executed(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=USER_RSYDOW,
            target_key=PROC_STUN,
            timestamp=ts,
        )
        spawned = Spawned(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=USER_RSYDOW,
            target_key=PROC_STUN,
            timestamp=ts,
        )
        assert executed.canonical_key() != spawned.canonical_key()
        # The discriminator is in the edge_type position (index 2)
        assert executed.canonical_key()[2] == "Executed"
        assert spawned.canonical_key()[2] == "Spawned"

    def test_merge_unions_confirmed_by(self) -> None:
        """STUN.exe execution attested by amcache + evtx + prefetch -> 'confirmed'."""
        ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
        e1 = Executed(
            evidence_hash=VALID_HASH,
            derivation="amcache",
            source_key=TASK_STUN,
            target_key=PROC_STUN,
            timestamp=ts,
            confirmed_by=["amcache"],
        )
        e2 = Executed(
            evidence_hash=VALID_HASH,
            derivation="evtx_4688",
            source_key=TASK_STUN,
            target_key=PROC_STUN,
            timestamp=ts,
            confirmed_by=["evtx_4688", "prefetch"],
        )
        e1.merge_into(e2)
        assert sorted(e1.confirmed_by) == sorted(["amcache", "evtx_4688", "prefetch"])
        assert e1.confidence == "confirmed"


# =============================================================================
# Connected
# =============================================================================


ENDPOINT_SMB = ("NetworkEndpoint", "SMB", "172.16.6.12", 445)


class TestConnected:
    """Schema section 3.4 — Connected edge."""

    def test_minimal_construction(self) -> None:
        e = Connected(
            evidence_hash=VALID_HASH,
            derivation="vol windows.netscan",
            source_key=PROC_STUN,
            target_key=ENDPOINT_SMB,
        )
        assert e.direction is None
        assert e.local_port is None
        assert e.confidence == "inferred"

    def test_lateral_movement_pattern(self) -> None:
        """The SRL case finding: net.exe -> 172.16.6.12:445."""
        ts = datetime(2023, 1, 25, 15, 0, 0, tzinfo=timezone.utc)
        proc_net = ("Process", "rd01", 9128, None)
        e = Connected(
            evidence_hash=VALID_HASH,
            derivation="vol windows.netscan",
            source_key=proc_net,
            target_key=ENDPOINT_SMB,
            timestamp=ts,
            direction="outbound",
            state="ESTABLISHED",
            confirmed_by=["netscan", "evtx_4688_with_cmdline"],
        )
        assert e.direction == "outbound"
        assert e.confidence == "confirmed"

    def test_local_port_validation(self) -> None:
        with pytest.raises(ValidationError):
            Connected(
                evidence_hash=VALID_HASH,
                derivation="src",
                source_key=PROC_STUN,
                target_key=ENDPOINT_SMB,
                local_port=70000,
            )

    def test_canonical_key_includes_type(self) -> None:
        ts = datetime(2023, 1, 25, 15, 0, 0, tzinfo=timezone.utc)
        e = Connected(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=ENDPOINT_SMB,
            timestamp=ts,
        )
        assert e.canonical_key()[2] == "Connected"

    def test_merge_unions_confirmed_by(self) -> None:
        ts = datetime(2023, 1, 25, 15, 0, 0, tzinfo=timezone.utc)
        e1 = Connected(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            source_key=PROC_STUN,
            target_key=ENDPOINT_SMB,
            timestamp=ts,
            confirmed_by=["netscan"],
        )
        e2 = Connected(
            evidence_hash=VALID_HASH,
            derivation="evtx_5156",
            source_key=PROC_STUN,
            target_key=ENDPOINT_SMB,
            timestamp=ts,
            confirmed_by=["evtx_5156"],
        )
        e1.merge_into(e2)
        assert e1.confidence == "confirmed"


# =============================================================================
# Wrote / Read / Deleted (filesystem activity)
# =============================================================================


FILE_STUN = ("File", "rd01", "c:/windows/system32/stun.exe")


class TestWrote:
    """Schema section 3.10 — Wrote edge."""

    def test_minimal_construction(self) -> None:
        e = Wrote(
            evidence_hash=VALID_HASH,
            derivation="evtx_4663",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
        )
        assert e.operation is None
        assert e.bytes_written is None
        assert e.confidence == "inferred"

    def test_full_construction(self) -> None:
        ts = datetime(2023, 1, 25, 14, 52, 0, tzinfo=timezone.utc)
        e = Wrote(
            evidence_hash=VALID_HASH,
            derivation="usn_journal",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
            timestamp=ts,
            operation="create",
            bytes_written=12345,
            confirmed_by=["usn_journal", "evtx_4663"],
        )
        assert e.operation == "create"
        assert e.bytes_written == 12345
        assert e.confidence == "confirmed"

    def test_canonical_key_includes_type(self) -> None:
        e = Wrote(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
        )
        assert e.canonical_key()[2] == "Wrote"


class TestRead:
    """Schema section 3.11 — Read edge."""

    def test_minimal_construction(self) -> None:
        e = Read(
            evidence_hash=VALID_HASH,
            derivation="evtx_4663",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
        )
        assert e.confidence == "inferred"

    def test_canonical_key_distinguishes_from_wrote(self) -> None:
        ts = datetime(2023, 1, 25, 14, 52, 0, tzinfo=timezone.utc)
        read = Read(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
            timestamp=ts,
        )
        wrote = Wrote(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
            timestamp=ts,
        )
        assert read.canonical_key() != wrote.canonical_key()


class TestDeleted:
    """Schema section 3.12 — Deleted edge."""

    def test_minimal_construction(self) -> None:
        e = Deleted(
            evidence_hash=VALID_HASH,
            derivation="usn_journal",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
        )
        assert e.confidence == "inferred"

    def test_canonical_key_includes_type(self) -> None:
        e = Deleted(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
        )
        assert e.canonical_key()[2] == "Deleted"

    def test_merge_unions_confirmed_by(self) -> None:
        ts = datetime(2023, 1, 25, 16, 0, 0, tzinfo=timezone.utc)
        e1 = Deleted(
            evidence_hash=VALID_HASH,
            derivation="usn",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
            timestamp=ts,
            confirmed_by=["usn_journal"],
        )
        e2 = Deleted(
            evidence_hash=VALID_HASH,
            derivation="evtx",
            source_key=PROC_STUN,
            target_key=FILE_STUN,
            timestamp=ts,
            confirmed_by=["evtx_4660"],
        )
        e1.merge_into(e2)
        assert e1.confidence == "confirmed"
