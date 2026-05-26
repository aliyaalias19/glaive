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
