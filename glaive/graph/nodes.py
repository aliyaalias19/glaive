"""GLAIVE evidence graph — typed node subclasses.

Each subclass extends Node and implements:
  - node_type ClassVar
  - Type-specific fields per docs/EVIDENCE_GRAPH_SCHEMA.md section 2
  - canonical_key() per schema section 5 identity rules
  - merge_into(other) per schema section 5 merge rules
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from pydantic import Field

from glaive.graph.base import Node


class Host(Node):
    """A computer in the investigation. The top-level scope.

    Schema reference: section 2.1.
    Identity: machine_guid if present, else hostname.
    """

    node_type: ClassVar[str] = "Host"

    hostname: str = Field(..., description="Friendly name (e.g., 'rd01').")
    machine_guid: str | None = Field(
        None,
        description="From SOFTWARE\\Microsoft\\Cryptography\\MachineGuid. Ground-truth identifier.",
    )
    os_version: str | None = Field(None, description="e.g., 'Windows Server 2022'.")
    timezone: str = Field("UTC", description="Host's reported timezone; analysis is in UTC.")
    network_subnet: str | None = Field(None, description="e.g., '172.16.6.0/24'.")

    def canonical_key(self) -> tuple[Any, ...]:
        """Identity: machine_guid if present, else hostname.

        We always return a 2-tuple ('Host', identity_value) so all node
        canonical keys share the same shape: (node_type, *identity_fields).
        """
        identity = self.machine_guid if self.machine_guid is not None else self.hostname
        return ("Host", identity)

    def merge_into(self, other: "Node") -> None:
        """Merge another Host observation into this one.

        Rule: first observation wins for static fields. Only fill in null fields
        from `other`. We never overwrite a known value with a different one
        (disagreements would land in a future `disagreements` field — v2).
        """
        if not isinstance(other, Host):
            raise TypeError(f"Cannot merge {type(other).__name__} into Host")

        # Fill any null fields from `other`
        if self.machine_guid is None and other.machine_guid is not None:
            self.machine_guid = other.machine_guid
        if self.os_version is None and other.os_version is not None:
            self.os_version = other.os_version
        if self.network_subnet is None and other.network_subnet is not None:
            self.network_subnet = other.network_subnet
        # hostname and timezone are required/defaulted, so no null-fill needed

class User(Node):
    """A user account (local, domain, service, or well-known).

    Schema reference: section 2.6.
    Identity: sid alone (globally unique by Windows design).

    Note: not host-scoped. A domain user is the same node across all hosts.
    Well-known SIDs (SYSTEM = S-1-5-18, NETWORK SERVICE = S-1-5-20) are
    intentionally shared across hosts in the graph.
    """

    node_type: ClassVar[str] = "User"

    sid: str = Field(
        ...,
        min_length=5,
        description="Security Identifier, e.g., 'S-1-5-21-...'",
    )
    username: str | None = Field(None, description="e.g., 'rsydow-a'.")
    domain: str | None = Field(None, description="e.g., 'SHIELDBASE'.")
    account_type: str | None = Field(
        None,
        description="One of: 'local', 'domain', 'service', 'well-known', or None if unknown.",
    )

    def canonical_key(self) -> tuple[Any, ...]:
        """Identity is SID alone."""
        return ("User", self.sid)

    def merge_into(self, other: "Node") -> None:
        """First non-null wins for username/domain. Take more-specific account_type.

        Schema section 5.6.
        """
        if not isinstance(other, User):
            raise TypeError(f"Cannot merge {type(other).__name__} into User")

        if self.username is None and other.username is not None:
            self.username = other.username
        if self.domain is None and other.domain is not None:
            self.domain = other.domain

        specificity_rank = {"domain": 3, "local": 3, "service": 2, "well-known": 1, None: 0}
        self_rank = specificity_rank.get(self.account_type, 0)
        other_rank = specificity_rank.get(other.account_type, 0)
        if other_rank > self_rank:
            self.account_type = other.account_type


class NetworkEndpoint(Node):
    """A remote (protocol, addr, port) the host communicated with.

    Schema reference: section 2.5.
    Identity: (protocol, remote_addr, remote_port). Not host-scoped — same
    endpoint contacted by multiple hosts is one node, enabling C2 pivots.
    """

    node_type: ClassVar[str] = "NetworkEndpoint"

    protocol: str = Field(..., description="'TCP' / 'UDP' / 'SMB' / etc.")
    remote_addr: str = Field(..., description="IP address.")
    remote_port: int = Field(..., ge=0, le=65535, description="0-65535.")
    domain: str | None = Field(None, description="Resolved hostname if captured.")
    is_internal: bool = Field(
        False,
        description="True if remote_addr is RFC1918 private space (10/8, 172.16/12, 192.168/16) or loopback.",
    )

    def canonical_key(self) -> tuple[Any, ...]:
        return ("NetworkEndpoint", self.protocol, self.remote_addr, self.remote_port)

    def merge_into(self, other: "Node") -> None:
        """Fill null domain from other. is_internal is deterministic from addr."""
        if not isinstance(other, NetworkEndpoint):
            raise TypeError(f"Cannot merge {type(other).__name__} into NetworkEndpoint")

        if self.domain is None and other.domain is not None:
            self.domain = other.domain
