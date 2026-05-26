"""GLAIVE evidence graph — typed edge subclasses.

Each subclass extends Edge or MultiSourceEdge and implements:
  - edge_type ClassVar
  - Type-specific extra properties per docs/EVIDENCE_GRAPH_SCHEMA.md section 3

The edge_type is part of canonical_key(), so two edges of different types
between the same nodes are distinct.
"""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from pydantic import Field

from glaive.graph.base import Edge, MultiSourceEdge


# =============================================================================
# Family A — process activity (all use MultiSourceEdge for confirmed_by)
# =============================================================================


class Spawned(MultiSourceEdge):
    """Parent process created a child process.

    Schema section 3.1.
    Direction: Process(parent) -> Process(child).

    Earnability: pstree, EVTX 4688.
    """

    edge_type: ClassVar[str] = "Spawned"


class Executed(MultiSourceEdge):
    """A non-process entity caused a process to run.

    Schema section 3.3.
    Direction: (User | ScheduledTask | Service) -> Process.
    Distinct from Spawned (process-to-process).

    The high-value execution edge — many sources can attest:
    Prefetch, Amcache, Shimcache, EVTX 4688, BAM/DAM, UserAssist, SRUM.
    """

    edge_type: ClassVar[str] = "Executed"

    command_line: str | None = Field(
        None, description="Full command line invoked by the executor, if known."
    )


class Connected(MultiSourceEdge):
    """A process opened a network connection to an endpoint.

    Schema section 3.4.
    Direction: Process -> NetworkEndpoint.

    Earnability: vol windows.netstat / netscan, EVTX 5156.
    """

    edge_type: ClassVar[str] = "Connected"

    direction: str | None = Field(
        None, description="'outbound' / 'inbound' / 'listening'."
    )
    local_port: int | None = Field(None, ge=0, le=65535)
    state: str | None = Field(
        None, description="e.g., 'ESTABLISHED', 'CLOSE_WAIT', 'LISTENING'."
    )


class Wrote(MultiSourceEdge):
    """Process created or modified a file.

    Schema section 3.10.
    Direction: Process -> File.
    """

    edge_type: ClassVar[str] = "Wrote"

    operation: str | None = Field(
        None, description="'create' or 'modify'. None if unclear."
    )
    bytes_written: int | None = Field(None, ge=0)


class Read(MultiSourceEdge):
    """Process read a file.

    Schema section 3.11.
    Direction: Process -> File.
    """

    edge_type: ClassVar[str] = "Read"


class Deleted(MultiSourceEdge):
    """Process deleted a file.

    Schema section 3.12.
    Direction: Process -> File.

    Earnability: USN journal, EVTX 4660.
    """

    edge_type: ClassVar[str] = "Deleted"


# =============================================================================
# Family B — auth and persistence
# =============================================================================


class AuthenticatedAs(Edge):
    """A process runs in the security context of a user — the state, not the event.

    Schema section 3.5.
    Direction: Process -> User.

    NOT a MultiSourceEdge: this is a state-of-being, not an event. Two
    ingestions of 'this process runs as this user' just confirm a constant.

    Earnability: vol windows.getsids + EVTX 4624 (logon_id cross-reference).
    """

    edge_type: ClassVar[str] = "AuthenticatedAs"

    logon_type: int | None = Field(
        None, description="EVTX logon type: 2=interactive, 3=network, 10=remote, etc."
    )
    is_elevated: bool = Field(False, description="True if process has admin privileges.")


class Logon(MultiSourceEdge):
    """An authentication event — distinct from AuthenticatedAs (which is state).

    Schema section 3.6.
    Direction: User -> Host.

    Earnability: EVTX 4624 (success), 4625 (failure), 4648 (explicit creds),
    1149 (RDP authentication success).
    """

    edge_type: ClassVar[str] = "Logon"

    logon_type: int | None = Field(
        None, description="2=interactive, 3=network, 10=remote interactive, etc."
    )
    source_ip: str | None = Field(None, description="Source IP for network/RDP logons.")
    success: bool = Field(True, description="4624 -> true, 4625 -> false.")
    failure_reason: str | None = Field(
        None, description="Populated when success=False."
    )


class Persisted(MultiSourceEdge):
    """A file is being persisted via an autorun mechanism.

    Schema section 3.9.
    Direction: File -> (RegistryKey | ScheduledTask | Service).

    Often confidence='inferred' since this is cross-correlation, not a
    single tool's direct output.
    """

    edge_type: ClassVar[str] = "Persisted"

    mechanism: str | None = Field(
        None,
        description="'run_key' / 'scheduled_task' / 'service' / 'wmi_subscription_v2'.",
    )


# =============================================================================
# Family C — structural references
# =============================================================================


class Loaded(MultiSourceEdge):
    """A user-space DLL loaded into a process, or a driver loaded into the kernel.

    Schema section 3.2.
    Direction: Process -> Module (user-space) or Host -> Module(is_kernel=True).

    Earnability: vol windows.dlllist (DLLs), windows.modules / modscan (drivers).
    """

    edge_type: ClassVar[str] = "Loaded"

    load_address: int | None = Field(None, ge=0, description="Where the module loaded.")


class Modified(MultiSourceEdge):
    """Process changed a registry key.

    Schema section 3.7.
    Direction: Process -> RegistryKey.

    Earnability: EVTX 4657 (registry value modified, audit required),
    registry transaction logs.
    """

    edge_type: ClassVar[str] = "Modified"

    operation: str | None = Field(
        None, description="'create' / 'update' / 'delete'."
    )
    old_value: str | bytes | None = Field(None)
    new_value: str | bytes | None = Field(None)


class References(Edge):
    """An artifact names a file path, regardless of whether the file exists.

    Schema section 3.8.
    Direction: (RegistryKey | ScheduledTask | Service) -> File.

    NOT a MultiSourceEdge: each reference is typically from one specific source.

    The negative-evidence partner: a References edge to a File with
    on_disk=False is the canonical 'deleted/missing malware' pattern
    (e.g., atmfd.dll in Autoruns but absent from filesystem).
    """

    edge_type: ClassVar[str] = "References"

    reference_type: str = Field(
        ...,
        description="'autorun' / 'task_action' / 'service_image' / 'shimcache' / 'amcache'.",
    )
