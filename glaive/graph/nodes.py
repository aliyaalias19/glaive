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


def _normalize_path(path: str) -> str:
    """Normalize a Windows path for canonical identity.

    Rules from schema section 5.3:
      - Backslashes -> forward slashes
      - Lowercase (NTFS default semantics)
      - Strip NT object manager prefix (\\??\\C:\\foo -> c:/foo)
    """
    p = path.replace("\\", "/")
    # Strip a leading slash if present (so "/??/" becomes "??/" and we match uniformly)
    if p.startswith("/"):
        p = p[1:]
    # Strip NT object manager prefix
    if p.startswith("??/"):
        p = p[3:]
    return p.lower()


class File(Node):
    """A file on disk — existing, deleted, or merely referenced.

    Schema reference: section 2.3.
    Identity: (host_hostname, full_path_normalized).

    Note: a file referenced by multiple artifacts (e.g., Autoruns) but absent
    from the live filesystem is the canonical negative-evidence pattern.
    Such a File has on_disk=False and a non-empty referenced_by list.
    """

    node_type: ClassVar[str] = "File"

    host_hostname: str = Field(..., description="Hostname of the host this file lives on.")
    full_path: str = Field(..., description="Full path; will be normalized for identity.")

    # Hash properties
    sha256: str | None = Field(None, description="SHA-256 of file content if computable.")
    md5: str | None = Field(None, description="MD5 of file content if computable.")

    # Size and MAC times
    size_bytes: int | None = Field(None, ge=0)
    mtime: datetime | None = Field(None, description="$STANDARD_INFORMATION modify time.")
    atime: datetime | None = Field(None, description="$STANDARD_INFORMATION access time.")
    ctime: datetime | None = Field(None, description="$STANDARD_INFORMATION create time (record change).")
    btime: datetime | None = Field(None, description="$STANDARD_INFORMATION birth time.")

    # Filesystem-position properties
    mft_record_number: int | None = Field(None, ge=0)
    is_deleted: bool = Field(False, description="True if fls marked it `*` or MFT recovered from slack.")
    is_orphan: bool = Field(False, description="Allocated inode, no dirent.")

    # The on_disk vs referenced distinction (the negative-evidence pattern)
    on_disk: bool = Field(
        False,
        description="True if a filesystem-source observed the file (fls/MFT/filescan). "
        "False = only referenced by other artifacts.",
    )
    referenced_by: list[str] = Field(
        default_factory=list,
        description="Artifacts that name this path: autoruns, shimcache, amcache, etc.",
    )

    def canonical_key(self) -> tuple[Any, ...]:
        """Identity is (host, normalized full_path)."""
        return ("File", self.host_hostname, _normalize_path(self.full_path))

    def merge_into(self, other: "Node") -> None:
        """Merge per schema section 5.3.

        - Null scalars filled from other
        - Hashes: if both set and differ, this is a logic error (different file)
        - Timestamps: take earliest mtime/ctime/btime; latest atime
        - referenced_by: union
        - on_disk: OR — any source confirming disk presence wins
        - is_deleted, is_orphan: latest source wins (file state evolves)
        """
        if not isinstance(other, File):
            raise TypeError(f"Cannot merge {type(other).__name__} into File")

        # Hash conflict check — should not happen at this layer (caller's bug)
        if self.sha256 and other.sha256 and self.sha256 != other.sha256:
            raise ValueError(
                f"Hash conflict on {self.full_path}: {self.sha256[:8]} vs {other.sha256[:8]}. "
                "Different sha256 means different file; these should be distinct nodes."
            )

        # Fill null scalars
        if self.sha256 is None and other.sha256 is not None:
            self.sha256 = other.sha256
        if self.md5 is None and other.md5 is not None:
            self.md5 = other.md5
        if self.size_bytes is None and other.size_bytes is not None:
            self.size_bytes = other.size_bytes
        if self.mft_record_number is None and other.mft_record_number is not None:
            self.mft_record_number = other.mft_record_number

        # Timestamps — keep all known values, take the most informative
        # mtime/ctime/btime: earliest known wins (the "first time we know about")
        # atime: latest known wins (the "last time accessed")
        for ts_field in ("mtime", "ctime", "btime"):
            mine = getattr(self, ts_field)
            theirs = getattr(other, ts_field)
            if mine is None and theirs is not None:
                setattr(self, ts_field, theirs)
            elif mine is not None and theirs is not None and theirs < mine:
                setattr(self, ts_field, theirs)
        if self.atime is None and other.atime is not None:
            self.atime = other.atime
        elif self.atime is not None and other.atime is not None and other.atime > self.atime:
            self.atime = other.atime

        # on_disk: OR (any source confirming wins)
        self.on_disk = self.on_disk or other.on_disk

        # is_deleted / is_orphan: latest source wins. We approximate "latest" via
        # other being the incoming update. So OR is too aggressive (a single
        # earlier "yes deleted" observation would stick). Instead, take other's value.
        # The ingestion layer is responsible for not merging stale data.
        self.is_deleted = other.is_deleted if other.is_deleted else self.is_deleted
        self.is_orphan = other.is_orphan if other.is_orphan else self.is_orphan

        # referenced_by union with order-preserving dedup
        for ref in other.referenced_by:
            if ref not in self.referenced_by:
                self.referenced_by.append(ref)


def _normalize_registry_key_path(path: str) -> str:
    """Backslash -> forward, lowercase, strip leading/trailing slashes.

    Schema section 5.4. Consistent with File path normalization for query
    comparability across artifact types.
    """
    return path.replace("\\", "/").strip("/").lower()


class RegistryKey(Node):
    """A registry key, and optionally a value within it.

    Schema reference: section 2.4.
    Identity: (host, hive, key_path_normalized, value_name).

    value_name=None means "the key itself," not a specific value within it.
    """

    node_type: ClassVar[str] = "RegistryKey"

    host_hostname: str = Field(..., description="Hostname of the host.")
    hive_name: str = Field(..., description="e.g., 'SYSTEM', 'SOFTWARE', 'NTUSER.DAT'.")
    key_path: str = Field(..., description="e.g., 'CurrentControlSet\\\\Services\\\\pssdnsvc'.")
    value_name: str | None = Field(
        None,
        description="Value within the key. None = the key itself.",
    )
    value_data: str | bytes | None = Field(None, description="Value's data; None if not loaded.")
    value_type: str | None = Field(
        None, description="e.g., 'REG_SZ', 'REG_DWORD', 'REG_BINARY'."
    )
    last_write_time: datetime | None = Field(None, description="When the key was last written.")

    def canonical_key(self) -> tuple[Any, ...]:
        return (
            "RegistryKey",
            self.host_hostname,
            self.hive_name,
            _normalize_registry_key_path(self.key_path),
            self.value_name,
        )

    def merge_into(self, other: "Node") -> None:
        """Latest last_write_time wins for value_data (registry data mutates).

        Schema section 5.4.
        """
        if not isinstance(other, RegistryKey):
            raise TypeError(f"Cannot merge {type(other).__name__} into RegistryKey")

        # Take latest last_write_time
        if self.last_write_time is None and other.last_write_time is not None:
            self.last_write_time = other.last_write_time
            self.value_data = other.value_data
            self.value_type = other.value_type
        elif (
            self.last_write_time is not None
            and other.last_write_time is not None
            and other.last_write_time > self.last_write_time
        ):
            # Other is newer — take its data
            self.last_write_time = other.last_write_time
            self.value_data = other.value_data
            self.value_type = other.value_type
        else:
            # Self is at least as new; fill any nulls from other for type metadata
            if self.value_data is None and other.value_data is not None:
                self.value_data = other.value_data
            if self.value_type is None and other.value_type is not None:
                self.value_type = other.value_type


class Process(Node):
    """A running or formerly-running process on a host.

    Schema reference: section 2.2.
    Identity: (host_hostname, pid, start_time) — three-tuple.

    Why not include image_path in identity? A hollowed process keeps its
    original image_path but executes different code. We want that to be one
    process node, not two. (image_path_is_anomalous lives as a query, not a
    stored property — see D10.)

    Why include start_time? PIDs are recycled. Two processes with the same PID
    at different times are different processes; start_time disambiguates.
    When start_time is None (tool didn't provide it), nodes with the same
    (host, pid, None) tuple merge — we accept this fuzziness over noise.
    """

    node_type: ClassVar[str] = "Process"

    host_hostname: str = Field(..., description="Hostname of the host this process ran on.")
    pid: int = Field(..., ge=0, description="Process ID.")
    name: str = Field(..., description="Process name, e.g., 'STUN.exe'.")

    # Optional but commonly populated
    image_path: str | None = Field(None, description="Full path to backing binary; None if hollowed/injected.")
    command_line: str | None = Field(None, description="Full command line.")
    parent_pid: int | None = Field(None, ge=0)
    start_time: datetime | None = Field(None, description="EPROCESS start time. Part of identity when present.")
    exit_time: datetime | None = Field(None)
    sha256: str | None = Field(None, description="SHA-256 of image_path file.")

    # Multi-source observation tracking (Schema 4.2)
    observed_by: list[str] = Field(
        default_factory=list,
        description="Tools/plugins that saw this process: 'psscan', 'pslist', 'pstree', 'evtx_4688', etc.",
    )

    # Disagreement tracking (Schema 5.2)
    disagreements: dict[str, list] = Field(
        default_factory=dict,
        description="Map of field name -> list of conflicting observed values across tools.",
    )

    def canonical_key(self) -> tuple[Any, ...]:
        """Identity: (host, pid, start_time). start_time can be None."""
        return ("Process", self.host_hostname, self.pid, self.start_time)

    def merge_into(self, other: "Node") -> None:
        """Merge another observation of the same process.

        Schema section 5.2 merge rules:
          - Null fields filled from other
          - observed_by union (order-preserving dedup)
          - exit_time: take the latest known
          - Non-identity conflicts -> record in disagreements; do not pick a winner
          - parent_pid conflicts go into disagreements (real cases of tool disagreement)
        """
        if not isinstance(other, Process):
            raise TypeError(f"Cannot merge {type(other).__name__} into Process")

        # Fill simple nullable scalars (no conflict logic needed when one is None)
        if self.image_path is None and other.image_path is not None:
            self.image_path = other.image_path
        elif (
            self.image_path is not None
            and other.image_path is not None
            and self.image_path != other.image_path
        ):
            self._record_disagreement("image_path", self.image_path, other.image_path)

        if self.command_line is None and other.command_line is not None:
            self.command_line = other.command_line
        elif (
            self.command_line is not None
            and other.command_line is not None
            and self.command_line != other.command_line
        ):
            self._record_disagreement("command_line", self.command_line, other.command_line)

        if self.parent_pid is None and other.parent_pid is not None:
            self.parent_pid = other.parent_pid
        elif (
            self.parent_pid is not None
            and other.parent_pid is not None
            and self.parent_pid != other.parent_pid
        ):
            self._record_disagreement("parent_pid", self.parent_pid, other.parent_pid)

        if self.sha256 is None and other.sha256 is not None:
            self.sha256 = other.sha256
        elif (
            self.sha256 is not None
            and other.sha256 is not None
            and self.sha256 != other.sha256
        ):
            # Hash conflict on same (host, pid, start_time): the binary on disk changed
            # under us. Record disagreement but DON'T raise like File does — Process
            # identity is independent of binary content.
            self._record_disagreement("sha256", self.sha256, other.sha256)

        # exit_time: take latest known
        if self.exit_time is None and other.exit_time is not None:
            self.exit_time = other.exit_time
        elif (
            self.exit_time is not None
            and other.exit_time is not None
            and other.exit_time > self.exit_time
        ):
            self.exit_time = other.exit_time

        # observed_by: union with order preservation
        for src in other.observed_by:
            if src not in self.observed_by:
                self.observed_by.append(src)

        # disagreements: merge dicts, unioning lists
        for field, values in other.disagreements.items():
            existing = self.disagreements.setdefault(field, [])
            for v in values:
                if v not in existing:
                    existing.append(v)

    def _record_disagreement(self, field: str, mine: Any, theirs: Any) -> None:
        """Record both values when self and other disagree on a non-identity field.

        Schema section 5.2 — we do not pick a winner. Both values are retained
        so findings referencing this field can carry confidence='disputed'.
        """
        bucket = self.disagreements.setdefault(field, [])
        if mine not in bucket:
            bucket.append(mine)
        if theirs not in bucket:
            bucket.append(theirs)


class Process(Node):
    """A running or formerly-running process on a host.

    Schema reference: section 2.2.
    Identity: (host_hostname, pid, start_time).

    image_path is intentionally NOT in identity — supports hollowing detection
    as a finding rather than a node-identity ruling.
    """

    node_type: ClassVar[str] = "Process"

    host_hostname: str = Field(..., description="Hostname of the host.")
    pid: int = Field(..., ge=0, description="Process ID.")
    name: str = Field(..., description="Image base name, e.g., 'STUN.exe'.")
    image_path: str | None = Field(None, description="e.g., 'C:\\\\Windows\\\\System32\\\\STUN.exe'.")
    command_line: str | None = Field(None, description="Full command line if known.")
    parent_pid: int | None = Field(None, ge=0)
    start_time: datetime | None = Field(
        None, description="EPROCESS start time. None if unknown."
    )
    exit_time: datetime | None = Field(None, description="When process exited; None if running.")
    sha256: str | None = Field(None, description="SHA-256 of image_path file if computable.")

    # Multi-source identification pattern (Principle 4 + schema 4.2)
    observed_by: list[str] = Field(
        default_factory=list,
        description="Tools/plugins that observed this process: 'psscan', 'pslist', 'pstree', 'evtx_4688', etc.",
    )

    # Disagreements pattern (schema section 5)
    disagreements: dict[str, list] = Field(
        default_factory=dict,
        description="Conflicting non-identity observations from different tools. "
        "Key = field name, Value = list of {value, source} dicts.",
    )

    def canonical_key(self) -> tuple[Any, ...]:
        """Identity: (host, pid, start_time). Schema section 5.2."""
        return ("Process", self.host_hostname, self.pid, self.start_time)

    def _record_disagreement(self, field_name: str, value: Any, source: str) -> None:
        """Append a disagreeing value to the disagreements dict."""
        self.disagreements.setdefault(field_name, []).append(
            {"value": value, "source": source}
        )

    def merge_into(self, other: "Node") -> None:
        """Merge per schema section 5.2.

        - Null scalars filled from other
        - observed_by: union (dedup-preserved order)
        - Conflicting non-null scalars recorded in disagreements (no winner)
        - exit_time: take the latest (most recent observation wins)
        """
        if not isinstance(other, Process):
            raise TypeError(f"Cannot merge {type(other).__name__} into Process")

        # Track the source of `other` for disagreement records
        other_source = other.derivation

        # Scalar fields: fill nulls, record conflicts
        scalar_fields = ("image_path", "command_line", "parent_pid", "sha256")
        for field in scalar_fields:
            mine = getattr(self, field)
            theirs = getattr(other, field)
            if mine is None and theirs is not None:
                setattr(self, field, theirs)
            elif mine is not None and theirs is not None and mine != theirs:
                # Conflict — record both values, don't pick a winner
                self._record_disagreement(field, theirs, other_source)

        # name is required; if they differ it's a real disagreement too
        if self.name != other.name:
            self._record_disagreement("name", other.name, other_source)

        # exit_time: take latest known
        if self.exit_time is None and other.exit_time is not None:
            self.exit_time = other.exit_time
        elif (
            self.exit_time is not None
            and other.exit_time is not None
            and other.exit_time > self.exit_time
        ):
            self.exit_time = other.exit_time

        # observed_by: union with order-preserving dedup
        for obs in other.observed_by:
            if obs not in self.observed_by:
                self.observed_by.append(obs)

        # Merge other's accumulated disagreements into ours
        for field_name, conflicts in other.disagreements.items():
            self.disagreements.setdefault(field_name, []).extend(conflicts)


class ScheduledTask(Node):
    """A Windows Task Scheduler entry.

    Schema reference: section 2.7.
    Identity: (host_hostname, task_path).
    """

    node_type: ClassVar[str] = "ScheduledTask"

    host_hostname: str = Field(..., description="Hostname of the host.")
    task_path: str = Field(..., description="e.g., '\\\\Microsoft\\\\Windows\\\\STUN'.")
    author: str | None = Field(None, description="Task XML Author element.")
    command: str | None = Field(None, description="Task action: Exec/Command.")
    arguments: str | None = Field(None, description="Task action: Exec/Arguments.")
    trigger_type: str | None = Field(
        None, description="Boot / Logon / Time / Event / Daily / etc."
    )
    is_enabled: bool = Field(True, description="From task XML Settings/Enabled. Default true.")
    last_run_time: datetime | None = Field(None)

    # Disagreements pattern (same as Process)
    disagreements: dict[str, list] = Field(default_factory=dict)

    def canonical_key(self) -> tuple[Any, ...]:
        return ("ScheduledTask", self.host_hostname, self.task_path)

    def _record_disagreement(self, field_name: str, value: Any, source: str) -> None:
        self.disagreements.setdefault(field_name, []).append(
            {"value": value, "source": source}
        )

    def merge_into(self, other: "Node") -> None:
        """Fill nulls, record disagreements on command/arguments/trigger_type."""
        if not isinstance(other, ScheduledTask):
            raise TypeError(f"Cannot merge {type(other).__name__} into ScheduledTask")

        other_source = other.derivation

        scalar_fields = ("author", "command", "arguments", "trigger_type")
        for field in scalar_fields:
            mine = getattr(self, field)
            theirs = getattr(other, field)
            if mine is None and theirs is not None:
                setattr(self, field, theirs)
            elif mine is not None and theirs is not None and mine != theirs:
                self._record_disagreement(field, theirs, other_source)

        # is_enabled: take other's value (latest observation wins)
        # If you've observed it as disabled, that supersedes earlier "enabled" assumption
        if not other.is_enabled:
            self.is_enabled = False

        # last_run_time: take latest known
        if self.last_run_time is None and other.last_run_time is not None:
            self.last_run_time = other.last_run_time
        elif (
            self.last_run_time is not None
            and other.last_run_time is not None
            and other.last_run_time > self.last_run_time
        ):
            self.last_run_time = other.last_run_time

        # Merge accumulated disagreements
        for field_name, conflicts in other.disagreements.items():
            self.disagreements.setdefault(field_name, []).extend(conflicts)


class Service(Node):
    """A Windows service.

    Schema reference: section 2.8.
    Identity: (host_hostname, service_name).
    """

    node_type: ClassVar[str] = "Service"

    host_hostname: str = Field(..., description="Hostname of the host.")
    service_name: str = Field(..., description="e.g., 'pssdnsvc'.")
    display_name: str | None = Field(None)
    image_path: str | None = Field(None, description="Registry ImagePath value.")
    start_type: str | None = Field(
        None, description="'Auto' / 'Manual' / 'Disabled' / 'Boot' / 'System'."
    )
    service_account: str | None = Field(
        None, description="e.g., 'LocalSystem', 'LocalService'."
    )
    is_running: bool | None = Field(
        None, description="From memory svcscan; None if unknown."
    )

    # Disagreements pattern
    disagreements: dict[str, list] = Field(default_factory=dict)

    def canonical_key(self) -> tuple[Any, ...]:
        return ("Service", self.host_hostname, self.service_name)

    def _record_disagreement(self, field_name: str, value: Any, source: str) -> None:
        self.disagreements.setdefault(field_name, []).append(
            {"value": value, "source": source}
        )

    def merge_into(self, other: "Node") -> None:
        """Fill nulls, record disagreements. is_running: memory wins.

        Schema section 5.8.
        """
        if not isinstance(other, Service):
            raise TypeError(f"Cannot merge {type(other).__name__} into Service")

        other_source = other.derivation

        scalar_fields = ("display_name", "image_path", "start_type", "service_account")
        for field in scalar_fields:
            mine = getattr(self, field)
            theirs = getattr(other, field)
            if mine is None and theirs is not None:
                setattr(self, field, theirs)
            elif mine is not None and theirs is not None and mine != theirs:
                self._record_disagreement(field, theirs, other_source)

        # is_running: memory source takes precedence over registry-derived data
        # If self is None and other has a value, take it
        if self.is_running is None and other.is_running is not None:
            self.is_running = other.is_running
        elif (
            self.is_running is not None
            and other.is_running is not None
            and self.is_running != other.is_running
        ):
            # Conflict on is_running. Memory ("svcscan") wins.
            # Determine which derivation is the memory source.
            if "svcscan" in other.derivation.lower():
                self.is_running = other.is_running

        # Merge accumulated disagreements
        for field_name, conflicts in other.disagreements.items():
            self.disagreements.setdefault(field_name, []).extend(conflicts)


class Module(Node):
    """A DLL or driver loaded into a process or the kernel.

    Schema reference: section 2.9.
    Identity: (host_hostname, image_path_normalized, base_address).

    Drivers are collapsed into Module with is_kernel=True (v1 simplification).
    """

    node_type: ClassVar[str] = "Module"

    host_hostname: str = Field(..., description="Hostname of the host.")
    image_path: str = Field(..., description="Full path of the module image.")
    base_address: int = Field(..., ge=0, description="Load address in memory.")
    size: int | None = Field(None, ge=0, description="Image size in bytes.")
    sha256: str | None = Field(None, description="SHA-256 of image_path file if computable.")
    is_kernel: bool = Field(False, description="True for drivers loaded into the kernel.")

    # Multi-source identification (same pattern as Process)
    observed_by: list[str] = Field(
        default_factory=list,
        description="'dlllist' / 'modules' / 'modscan'. Hidden if modscan-only.",
    )

    def canonical_key(self) -> tuple[Any, ...]:
        return (
            "Module",
            self.host_hostname,
            _normalize_path(self.image_path),
            self.base_address,
        )

    def merge_into(self, other: "Node") -> None:
        """Standard null-fill + observed_by union. Hash conflict raises.

        Schema section 5.9.
        """
        if not isinstance(other, Module):
            raise TypeError(f"Cannot merge {type(other).__name__} into Module")

        # Hash conflict on same identity is a logic error (different module bytes)
        if self.sha256 and other.sha256 and self.sha256 != other.sha256:
            raise ValueError(
                f"Hash conflict on module {self.image_path} @ {self.base_address:#x}: "
                f"{self.sha256[:8]} vs {other.sha256[:8]}"
            )

        if self.sha256 is None and other.sha256 is not None:
            self.sha256 = other.sha256
        if self.size is None and other.size is not None:
            self.size = other.size

        # is_kernel should be deterministic from base_address range — don't allow flip
        if self.is_kernel != other.is_kernel:
            raise ValueError(
                f"is_kernel mismatch on module {self.image_path}: "
                f"{self.is_kernel} vs {other.is_kernel}. Different identity intended?"
            )

        # observed_by union with order-preserving dedup
        for obs in other.observed_by:
            if obs not in self.observed_by:
                self.observed_by.append(obs)


class AntivirusDetection(Node):
    """A Windows Defender detection event.

    Schema reference: section 2.10.
    Identity: (host_hostname, event_id, detection_time, threat_name).

    Each detection event is a distinct node — repeated detections of the
    same threat produce multiple nodes (one per event), enabling 'how many
    times was this killed?' queries.
    """

    node_type: ClassVar[str] = "AntivirusDetection"

    host_hostname: str = Field(..., description="Hostname of the host.")
    event_id: int = Field(..., description="1116 / 1117 / 1118 / 1119 / 5001.")
    threat_name: str = Field(..., description="e.g., 'Trojan:Win32/PowerRunner.A'.")
    detection_time: datetime = Field(..., description="EVTX timestamp (required for identity).")
    action_taken: str | None = Field(
        None, description="'Quarantined' / 'Removed' / 'Allowed' / etc."
    )
    file_path: str | None = Field(None, description="Path of the detected binary.")

    def canonical_key(self) -> tuple[Any, ...]:
        return (
            "AntivirusDetection",
            self.host_hostname,
            self.event_id,
            self.detection_time,
            self.threat_name,
        )

    def merge_into(self, other: "Node") -> None:
        """Trivial merge — identity is so specific that same-identity means
        the same event. Just fill nulls.
        """
        if not isinstance(other, AntivirusDetection):
            raise TypeError(f"Cannot merge {type(other).__name__} into AntivirusDetection")

        if self.action_taken is None and other.action_taken is not None:
            self.action_taken = other.action_taken
        if self.file_path is None and other.file_path is not None:
            self.file_path = other.file_path
