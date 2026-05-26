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

from glaive.graph.edges import AuthenticatedAs, Connected, Deleted, Executed, Loaded, Logon, Modified, Persisted, Read, References, Spawned, Wrote


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


# =============================================================================
# AuthenticatedAs
# =============================================================================


class TestAuthenticatedAs:
    """Schema section 3.5 — AuthenticatedAs edge (Process state)."""

    def test_minimal_construction(self) -> None:
        e = AuthenticatedAs(
            evidence_hash=VALID_HASH,
            derivation="vol windows.getsids",
            source_key=PROC_STUN,
            target_key=USER_RSYDOW,
        )
        assert e.logon_type is None
        assert e.is_elevated is False

    def test_full_construction(self) -> None:
        e = AuthenticatedAs(
            evidence_hash=VALID_HASH,
            derivation="getsids+evtx_4624",
            source_key=PROC_STUN,
            target_key=USER_RSYDOW,
            logon_type=10,
            is_elevated=True,
        )
        assert e.logon_type == 10
        assert e.is_elevated is True

    def test_canonical_key_includes_edge_type(self) -> None:
        e = AuthenticatedAs(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=USER_RSYDOW,
        )
        assert e.canonical_key()[2] == "AuthenticatedAs"

    def test_default_merge_is_noop(self) -> None:
        """AuthenticatedAs inherits plain Edge.merge_into() which is a no-op."""
        e1 = AuthenticatedAs(
            evidence_hash=VALID_HASH,
            derivation="src1",
            source_key=PROC_STUN,
            target_key=USER_RSYDOW,
            logon_type=10,
        )
        e2 = AuthenticatedAs(
            evidence_hash=VALID_HASH,
            derivation="src2",
            source_key=PROC_STUN,
            target_key=USER_RSYDOW,
            logon_type=3,
        )
        # Default Edge.merge_into is no-op — state of self preserved
        e1.merge_into(e2)
        assert e1.logon_type == 10


# =============================================================================
# Logon
# =============================================================================


HOST_RD01 = ("Host", "rd01")  # using hostname identity since no machine_guid


class TestLogon:
    """Schema section 3.6 — Logon edge (event)."""

    def test_minimal_construction(self) -> None:
        e = Logon(
            evidence_hash=VALID_HASH,
            derivation="evtx_4624",
            source_key=USER_RSYDOW,
            target_key=HOST_RD01,
        )
        assert e.success is True  # default
        assert e.source_ip is None
        assert e.failure_reason is None

    def test_rdp_logon_pattern(self) -> None:
        """The SRL case: rsydow-a logs onto rd01 via RDP from 172.15.1.20."""
        ts = datetime(2023, 1, 25, 14, 50, 0, tzinfo=timezone.utc)
        e = Logon(
            evidence_hash=VALID_HASH,
            derivation="evtx_4624 + evtx_1149",
            source_key=USER_RSYDOW,
            target_key=HOST_RD01,
            timestamp=ts,
            logon_type=10,
            source_ip="172.15.1.20",
            success=True,
            confirmed_by=["evtx_4624", "evtx_1149"],
        )
        assert e.logon_type == 10
        assert e.source_ip == "172.15.1.20"
        assert e.confidence == "confirmed"

    def test_failed_logon(self) -> None:
        """EVTX 4625 represents a failure event."""
        ts = datetime(2023, 1, 25, 14, 45, 0, tzinfo=timezone.utc)
        e = Logon(
            evidence_hash=VALID_HASH,
            derivation="evtx_4625",
            source_key=USER_RSYDOW,
            target_key=HOST_RD01,
            timestamp=ts,
            logon_type=3,
            success=False,
            failure_reason="Bad password",
        )
        assert e.success is False
        assert e.failure_reason == "Bad password"

    def test_canonical_key_includes_edge_type(self) -> None:
        ts = datetime(2023, 1, 25, 14, 50, 0, tzinfo=timezone.utc)
        e = Logon(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=USER_RSYDOW,
            target_key=HOST_RD01,
            timestamp=ts,
        )
        assert e.canonical_key()[2] == "Logon"

    def test_merge_unions_confirmed_by(self) -> None:
        ts = datetime(2023, 1, 25, 14, 50, 0, tzinfo=timezone.utc)
        e1 = Logon(
            evidence_hash=VALID_HASH,
            derivation="evtx_4624",
            source_key=USER_RSYDOW,
            target_key=HOST_RD01,
            timestamp=ts,
            confirmed_by=["evtx_4624"],
        )
        e2 = Logon(
            evidence_hash=VALID_HASH,
            derivation="evtx_1149",
            source_key=USER_RSYDOW,
            target_key=HOST_RD01,
            timestamp=ts,
            confirmed_by=["evtx_1149"],
        )
        e1.merge_into(e2)
        assert e1.confidence == "confirmed"


# =============================================================================
# Persisted
# =============================================================================


class TestPersisted:
    """Schema section 3.9 — Persisted edge."""

    def test_minimal_construction(self) -> None:
        e = Persisted(
            evidence_hash=VALID_HASH,
            derivation="cross_correlation",
            source_key=FILE_STUN,
            target_key=TASK_STUN,
        )
        assert e.mechanism is None
        assert e.confidence == "inferred"

    def test_stun_persistence_pattern(self) -> None:
        """The SRL case: STUN.exe persisted via scheduled task."""
        e = Persisted(
            evidence_hash=VALID_HASH,
            derivation="task_xml + mft_timing",
            source_key=FILE_STUN,
            target_key=TASK_STUN,
            mechanism="scheduled_task",
        )
        assert e.mechanism == "scheduled_task"

    def test_canonical_key_includes_edge_type(self) -> None:
        e = Persisted(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=FILE_STUN,
            target_key=TASK_STUN,
        )
        assert e.canonical_key()[2] == "Persisted"

    def test_merge_unions_confirmed_by(self) -> None:
        e1 = Persisted(
            evidence_hash=VALID_HASH,
            derivation="src1",
            source_key=FILE_STUN,
            target_key=TASK_STUN,
            mechanism="scheduled_task",
            confirmed_by=["task_xml"],
        )
        e2 = Persisted(
            evidence_hash=VALID_HASH,
            derivation="src2",
            source_key=FILE_STUN,
            target_key=TASK_STUN,
            mechanism="scheduled_task",
            confirmed_by=["evtx_4698"],
        )
        e1.merge_into(e2)
        assert e1.confidence == "confirmed"


# =============================================================================
# Loaded
# =============================================================================


MODULE_KERNEL32 = ("Module", "rd01", "c:/windows/system32/kernel32.dll", 0x7FFE12340000)


class TestLoaded:
    """Schema section 3.2 — Loaded edge."""

    def test_minimal_construction(self) -> None:
        e = Loaded(
            evidence_hash=VALID_HASH,
            derivation="vol windows.dlllist",
            source_key=PROC_STUN,
            target_key=MODULE_KERNEL32,
        )
        assert e.load_address is None
        assert e.confidence == "inferred"

    def test_with_load_address(self) -> None:
        e = Loaded(
            evidence_hash=VALID_HASH,
            derivation="dlllist",
            source_key=PROC_STUN,
            target_key=MODULE_KERNEL32,
            load_address=0x7FFE12340000,
        )
        assert e.load_address == 0x7FFE12340000

    def test_canonical_key_includes_edge_type(self) -> None:
        e = Loaded(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=MODULE_KERNEL32,
        )
        assert e.canonical_key()[2] == "Loaded"


# =============================================================================
# Modified
# =============================================================================


REGKEY_RUN_UPDATER = (
    "RegistryKey",
    "rd01",
    "NTUSER.DAT",
    "software/microsoft/windows/currentversion/run",
    "Updater",
)


class TestModified:
    """Schema section 3.7 — Modified edge."""

    def test_minimal_construction(self) -> None:
        e = Modified(
            evidence_hash=VALID_HASH,
            derivation="evtx_4657",
            source_key=PROC_STUN,
            target_key=REGKEY_RUN_UPDATER,
        )
        assert e.operation is None
        assert e.old_value is None
        assert e.new_value is None

    def test_with_operation_and_values(self) -> None:
        ts = datetime(2023, 1, 25, 14, 51, 0, tzinfo=timezone.utc)
        e = Modified(
            evidence_hash=VALID_HASH,
            derivation="evtx_4657",
            source_key=PROC_STUN,
            target_key=REGKEY_RUN_UPDATER,
            timestamp=ts,
            operation="create",
            new_value="C:\\Windows\\System32\\STUN.exe",
        )
        assert e.operation == "create"
        assert e.new_value == "C:\\Windows\\System32\\STUN.exe"

    def test_canonical_key_includes_edge_type(self) -> None:
        e = Modified(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=PROC_STUN,
            target_key=REGKEY_RUN_UPDATER,
        )
        assert e.canonical_key()[2] == "Modified"


# =============================================================================
# References  (negative-evidence partner)
# =============================================================================


FILE_ATMFD = ("File", "rd01", "c:/windows/system32/atmfd.dll")
REGKEY_AUTORUNS = (
    "RegistryKey",
    "rd01",
    "SOFTWARE",
    "microsoft/windows nt/currentversion/windows",
    "AppInit_DLLs",
)


class TestReferences:
    """Schema section 3.8 — References edge.

    This is the negative-evidence partner: a References edge to a File
    with on_disk=False represents 'deleted/missing malware' (e.g., atmfd.dll
    in Autoruns but absent from filesystem).
    """

    def test_minimal_construction(self) -> None:
        """reference_type is REQUIRED — the kind of reference matters."""
        e = References(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            source_key=REGKEY_AUTORUNS,
            target_key=FILE_ATMFD,
            reference_type="autorun",
        )
        assert e.reference_type == "autorun"

    def test_reference_type_required(self) -> None:
        """Without reference_type, validation should fail."""
        with pytest.raises(ValidationError):
            References(  # type: ignore[call-arg]
                evidence_hash=VALID_HASH,
                derivation="autorunsc",
                source_key=REGKEY_AUTORUNS,
                target_key=FILE_ATMFD,
            )

    def test_atmfd_pattern_construction(self) -> None:
        """The atmfd.dll canonical demo pattern: References edge to a File
        whose on_disk attribute would be False at the node level."""
        e = References(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            source_key=REGKEY_AUTORUNS,
            target_key=FILE_ATMFD,
            reference_type="autorun",
        )
        # The edge itself doesn't know about File.on_disk; that's a separate
        # query against the target node. This test verifies the edge construct
        # is sound for the demo pattern.
        assert e.target_key == FILE_ATMFD

    def test_canonical_key_includes_edge_type(self) -> None:
        e = References(
            evidence_hash=VALID_HASH,
            derivation="src",
            source_key=REGKEY_AUTORUNS,
            target_key=FILE_ATMFD,
            reference_type="autorun",
        )
        assert e.canonical_key()[2] == "References"

    def test_default_merge_is_noop(self) -> None:
        """References inherits plain Edge.merge_into() = no-op."""
        e1 = References(
            evidence_hash=VALID_HASH,
            derivation="src1",
            source_key=REGKEY_AUTORUNS,
            target_key=FILE_ATMFD,
            reference_type="autorun",
        )
        e2 = References(
            evidence_hash=VALID_HASH,
            derivation="src2",
            source_key=REGKEY_AUTORUNS,
            target_key=FILE_ATMFD,
            reference_type="autorun",
        )
        e1.merge_into(e2)  # should not raise, no-op
        assert e1.reference_type == "autorun"
