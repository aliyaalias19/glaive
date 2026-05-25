# Evidence Graph Schema — v1

> **Status:** Design complete (2026-05-25). Implementation begins Day 3.
> **Scope:** v1 represents every documented finding from the SRL-2018 case
> template. v2 candidates are listed in `docs/SCHEMA_V2_BACKLOG.md`.

The evidence graph is the central data structure of GLAIVE. Everything the
agent reasons about is a typed node or typed edge. Anything that cannot be
expressed as a node or edge cannot be claimed in a committed finding.

---

## 1. Design principles

Five principles govern every type in this schema. Future additions must
satisfy all five.

### Principle 1 — Earnability
Every node and edge type must be derivable from a specific named SIFT
tool's output. No speculative types. *Example:* `Process` is earnable
(`vol windows.psscan`). `PsychologicalProfile` is not — no tool produces it.

### Principle 2 — Expressibility
Every finding the agent can commit must be expressible as a graph query
over this schema. The Section 6 mapping demonstrates this for all 7
documented SRL findings.

### Principle 3 — Universal provenance
Every node and every edge carries three required fields:
- `evidence_hash` — SHA-256 of the source artifact in the content-addressed store
- `derivation` — tool execution string (e.g., `"vol windows.psscan rd01-memory.img@a3f2..."`)
- `observed_at` — UTC datetime when our ingestion saw this

These are enforced by Pydantic at ingestion. No untraceable graph elements.

### Principle 4 — Negative evidence is first-class
A finding can be supported by *absence* — e.g., "process observed by `psscan`
but not by `pslist`" indicates hiding. To enable this, nodes that can be
discovered by multiple tools carry an `observed_by: list[str]` attribute.
Findings query the list, including its negations.

### Principle 5 — v1/v2 separation
This document specifies v1. Deferred types go in
`docs/SCHEMA_V2_BACKLOG.md` and do not creep into v1 without a
DECISIONS.md entry.

---

## 2. Node types (10)

Every node type lists its identifier, properties, and a named SIFT tool
that produces it (satisfying Principle 1).

### 2.1 Host

The top-level scope. Everything else lives under a Host.

**Identity:** `machine_guid` if present, else `hostname` fallback.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `hostname` | str | `Control\ComputerName` registry value |
| `machine_guid` | str \| None | `SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| `os_version` | str \| None | `vol windows.info` or registry |
| `timezone` | str | `Control\TimeZoneInformation` |
| `network_subnet` | str \| None | network config or known topology |

**Earnability:** `RECmd` on SYSTEM hive, or `vol windows.info`.

### 2.2 Process

A running or formerly-running process on a host.

**Identity:** `(host_hostname, pid, start_time)` — three-tuple.
Excludes `image_path` (so hollowed processes remain one node) and
includes `start_time` to handle PID recycling.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `pid` | int | psscan / pslist / EVTX 4688 |
| `name` | str | psscan |
| `image_path` | str \| None | psscan; null if no on-disk backing |
| `command_line` | str \| None | `windows.cmdline` or EVTX 4688 |
| `parent_pid` | int \| None | pstree |
| `start_time` | datetime \| None | EPROCESS / EVTX 4688 |
| `exit_time` | datetime \| None | psscan |
| `sha256` | str \| None | hash of image_path file |
| `is_hidden` | bool | *computed:* psscan ∈ observed_by AND pslist ∉ observed_by |
| `observed_by` | list[str] | which tools/plugins saw this |
| `disagreements` | dict | conflicting observations from different tools |

**Earnability:** `vol windows.psscan / pslist / pstree / cmdline`, EVTX 4688.

### 2.3 File

A file on disk — existing, deleted, or merely referenced.

**Identity:** `(host_hostname, full_path_normalized)`. Path normalization:
backslash → forward slash, lowercase, strip NT object manager prefix
(`\??\C:\` → `C:/`).

**Properties:**
| Field | Type | Source |
|---|---|---|
| `full_path` | str | normalized path |
| `sha256` | str \| None | MFTECmd hash or filescan |
| `md5` | str \| None | MFTECmd hash |
| `size_bytes` | int \| None | MFT |
| `mtime` | datetime \| None | MFT $STANDARD_INFORMATION |
| `atime` | datetime \| None | MFT $STANDARD_INFORMATION |
| `ctime` | datetime \| None | MFT $STANDARD_INFORMATION |
| `btime` | datetime \| None | MFT $STANDARD_INFORMATION (birth) |
| `mft_record_number` | int \| None | MFTECmd |
| `is_deleted` | bool | fls `*` prefix or MFT slack |
| `is_orphan` | bool | allocated inode, no dirent |
| `on_disk` | bool | observed by fls/MFT (vs. only referenced) |
| `referenced_by` | list[str] | which artifacts cite this file path |

**Earnability:** sleuthkit `fls`, `MFTECmd`, `vol windows.filescan`, registry references.

### 2.4 RegistryKey

A registry key (and optionally a value within it).

**Identity:** `(host_hostname, hive_name, key_path_normalized, value_name)`.
`value_name = None` represents the key itself, not any specific value.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `hive_name` | str | SYSTEM / SOFTWARE / NTUSER.DAT / etc. |
| `key_path` | str | normalized lowercase path |
| `value_name` | str \| None | value within the key |
| `value_data` | str \| bytes \| None | value's data |
| `value_type` | str \| None | REG_SZ / REG_DWORD / etc. |
| `last_write_time` | datetime \| None | hive metadata |

**Earnability:** `RECmd`, `regipy`, `rip.pl`, `vol windows.registry.printkey`.

### 2.5 NetworkEndpoint

A remote address+port the host communicated with. **Not host-scoped** —
the same endpoint can be talked to by multiple hosts (useful for C2 pivots).

**Identity:** `(protocol, remote_addr, remote_port)`.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `protocol` | str | "TCP" / "UDP" / "SMB" |
| `remote_addr` | str | IP address |
| `remote_port` | int | port number |
| `domain` | str \| None | resolved hostname if captured |
| `is_internal` | bool | RFC1918 private space check |

**Earnability:** `vol windows.netstat / netscan`, EVTX 5156, 1149.

### 2.6 User

A user account (local, domain, service, or well-known).

**Identity:** `sid` alone — globally unique by Windows design.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `sid` | str | EVTX, getsids, SAM hive |
| `username` | str \| None | EVTX or registry |
| `domain` | str \| None | EVTX or registry |
| `account_type` | str \| None | local / domain / service / well-known |

**Earnability:** `vol windows.getsids`, EVTX 4624/4625, SAM hive.

### 2.7 ScheduledTask

A Windows Task Scheduler entry.

**Identity:** `(host_hostname, task_path)` — e.g., `\Microsoft\Windows\STUN`.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `task_path` | str | XML filename or EVTX |
| `author` | str \| None | task XML Author element |
| `command` | str \| None | task XML Action/Exec/Command |
| `arguments` | str \| None | task XML Action/Exec/Arguments |
| `trigger_type` | str \| None | task XML Triggers (boot/logon/time/event) |
| `is_enabled` | bool | task XML Settings/Enabled |
| `last_run_time` | datetime \| None | task XML LastRunTime |

**Earnability:** XMLs in `Windows\System32\Tasks\`, EVTX 4698, EVTX TaskScheduler 106.

### 2.8 Service

A Windows service.

**Identity:** `(host_hostname, service_name)`.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `service_name` | str | registry Services key or svcscan |
| `display_name` | str \| None | registry |
| `image_path` | str \| None | registry ImagePath value |
| `start_type` | str \| None | Auto / Manual / Disabled / Boot |
| `service_account` | str \| None | LocalSystem / LocalService / etc. |
| `is_running` | bool \| None | svcscan (memory state) |

**Earnability:** `vol windows.svcscan`, registry `Services` keys.

### 2.9 Module

A DLL or driver loaded into a process or the kernel.

**Identity:** `(host_hostname, image_path_normalized, base_address)`.
Same DLL at different base addresses (different processes, ASLR) = different
nodes.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `image_path` | str | dlllist / modules |
| `base_address` | int | dlllist / modules |
| `size` | int \| None | dlllist |
| `sha256` | str \| None | hash if computable |
| `is_kernel` | bool | true for drivers (collapsed from separate Driver type in v1) |
| `is_hidden` | bool | *computed:* modscan ∈ observed_by AND modules ∉ observed_by |
| `observed_by` | list[str] | dlllist / modules / modscan |

**Earnability:** `vol windows.dlllist / modules / modscan`.

### 2.10 AntivirusDetection

A Windows Defender detection event. Each detection is a distinct node.

**Identity:** `(host_hostname, event_id, detection_time, threat_name)`.

**Properties:**
| Field | Type | Source |
|---|---|---|
| `event_id` | int | 1116 / 1117 / 1118 / 1119 / 5001 |
| `threat_name` | str | e.g., "Trojan:Win32/PowerRunner.A" |
| `detection_time` | datetime | EVTX timestamp |
| `action_taken` | str \| None | Quarantined / Removed / Allowed |
| `file_path` | str \| None | path of the detected binary |

**Earnability:** EVTX `Microsoft-Windows-Windows Defender%4Operational.evtx`.

---

## 3. Edge types (12)

Every edge type lists its direction, properties beyond the universal three,
and an example finding it enables. All edges carry the universal three plus
`timestamp` (when the forensic event occurred, distinct from `observed_at`).

### 3.1 Spawned — Process → Process

Parent process created a child process.

**Extra properties:** `confirmed_by: list[str]`, `confidence`.

**Earnability:** pstree, EVTX 4688.

**Example:** `Process(svchost.exe, pid=1244) → Spawned → Process(STUN.exe, pid=1912)`.

### 3.2 Loaded — Process → Module  *or*  Host → Module(is_kernel=True)

A user-space DLL loaded into a process, or a driver loaded into the kernel.

**Extra properties:** `load_address: int \| None`.

**Earnability:** dlllist, modules.

### 3.3 Executed — (User \| ScheduledTask \| Service) → Process

A non-process entity caused a process to run. Distinct from `Spawned`
(which is process-to-process).

**Extra properties:** `command_line`, `confirmed_by`, `confidence`.

**Earnability:** Prefetch, Amcache, Shimcache (existence only), EVTX 4688,
BAM/DAM, UserAssist, SRUM.

**Example:** `ScheduledTask("\STUN") → Executed → Process(STUN.exe)`.

### 3.4 Connected — Process → NetworkEndpoint

Process opened a connection to a network endpoint.

**Extra properties:** `direction` (outbound/inbound/listening), `local_port`,
`state`, `confirmed_by`, `confidence`.

**Earnability:** netstat, netscan, EVTX 5156.

**Example:** `Process(net.exe, pid=9128) → Connected → NetworkEndpoint(SMB, 172.16.6.12, 445)`.

### 3.5 AuthenticatedAs — Process → User

A process is running in the security context of a user. The *state*, not
the event.

**Extra properties:** `logon_type`, `is_elevated`.

**Earnability:** getsids, EVTX 4624 cross-referenced.

### 3.6 Logon — User → Host

An authentication event. The *event*, distinct from `AuthenticatedAs` (state).

**Extra properties:** `logon_type`, `source_ip`, `success`, `failure_reason`,
`confirmed_by`.

**Earnability:** EVTX 4624 (success), 4625 (failure), 4648, 1149 (RDP).

### 3.7 Modified — Process → RegistryKey

Process changed a registry key.

**Extra properties:** `operation` (create/update/delete), `old_value`, `new_value`.

**Earnability:** EVTX 4657, registry transaction logs.

### 3.8 References — (RegistryKey \| ScheduledTask \| Service) → File

An artifact *names* a file path, regardless of whether the file exists on disk.

**Extra properties:** `reference_type` (autorun / task_action / service_image / shimcache / amcache).

**Earnability:** Run keys, task XMLs, service ImagePath, Shimcache, Amcache.

**Example:** *"atmfd.dll in Autoruns but absent from disk"* is
`RegistryKey(Autoruns) → References → File(atmfd.dll)` where
`File.on_disk == False`. **Canonical negative-evidence demo.**

### 3.9 Persisted — File → (RegistryKey \| ScheduledTask \| Service)

A file is being persisted via an autorun mechanism.

**Extra properties:** `mechanism` (run_key / scheduled_task / service / wmi_subscription_v2).

**Earnability:** cross-correlation of References + creation timing.

**Example:** `File(STUN.exe) → Persisted → ScheduledTask("\STUN")` with `mechanism="scheduled_task"`.

### 3.10 Wrote — Process → File

Process created or modified a file.

**Extra properties:** `operation` (create/modify), `bytes_written`, `confirmed_by`.

**Earnability:** EVTX 4663 (write access), USN journal.

### 3.11 Read — Process → File

Process read a file.

**Extra properties:** `confirmed_by`.

**Earnability:** EVTX 4663 (read access).

### 3.12 Deleted — Process → File

Process deleted a file.

**Extra properties:** `confirmed_by`.

**Earnability:** USN journal, EVTX 4660.

---

## 4. Property patterns

Six conventions that repeat across types, defined once here so subclass
Pydantic models stay consistent.

### 4.1 The universal three (Principle 3)
Every node and edge: `evidence_hash`, `derivation`, `observed_at`.

### 4.2 `observed_by` — multi-source identification
List of tool/plugin names that saw this node. Enables negative-evidence
queries (Principle 4). Applies to `Process`, `Module`.

### 4.3 `referenced_by` — multi-source citation
List of artifacts that *mention* a file path without observing the file
itself. Applies to `File`. The "deleted malware" signature is
`referenced_by != [] AND on_disk == False`.

### 4.4 `confirmed_by` — multi-source corroboration on edges
List of sources that independently attest to an event. Applies to edges
representing discrete events. Drives the `confidence` field:
- `len(confirmed_by) >= 2` → `confidence = "confirmed"`
- `len(confirmed_by) == 1` → `confidence = "suspected"`
- `len(confirmed_by) == 0` AND derived via graph inference → `confidence = "inferred"`

### 4.5 Computed boolean flags
Booleans like `Process.is_hidden`, `Module.is_hidden`, `File.on_disk` are
`@computed_field` in Pydantic — derived from observed_by/referenced_by
data, not stored independently. **Anomaly judgments live in queries
(`glaive/queries/`), not as stored properties.** (See DECISIONS.md D10.)

### 4.6 Timestamps — never inferred
All timestamps are UTC. If a tool didn't provide a timestamp, the field is
`None`. The schema never computes a "best guess" timestamp. Protects
accuracy and audit clarity.

---

## 5. Canonicalization

When two ingestions produce data about "the same" thing, how do we
merge them?

Each node type has exactly one **canonical identity tuple** and one
**merge rule**. See Section 2 for the identity tuple per type.

**Merge rules in general:**
- Properties null in one observation and set in another → use the set value
- Multi-source list fields (`observed_by`, `referenced_by`, `confirmed_by`) → union
- Conflicting non-identity values → store both in `disagreements`; do not pick a winner
- `exit_time`, `last_write_time`, etc. → take the latest

**Disagreement principle:** When two tools report contradictory values
(e.g., different command lines for the same process), the schema retains
both. A finding referencing such a property carries `confidence="disputed"`.
We do not silently pick a winner.

**Edge canonical identity:** `(source, target, edge_type, timestamp)`.
Two edges of the same type between the same nodes at the exact same
timestamp are merged (their `confirmed_by` lists unioned). Different
timestamps = different edges.

---

## 6. SRL ground truth → schema mapping (Principle 2 proof)

The schema's correctness was tested by attempting to express every
documented SRL finding as a graph query before implementation began.

| Finding | Query strategy | Status |
|---|---|---|
| STUN.exe parent process | Process by (host, pid, image_path) + incoming Spawned edge | ✅ |
| Execution chain ScheduledTask → STUN → svchost → taskhostw | Chain of Executed + Spawned edges | ✅ |
| msedge.exe masquerading | Process name vs image_path query against known-paths catalog | ✅ via query |
| pssdnsvc.exe name/path mismatch | Service name vs image_path query | ✅ via query |
| atmfd.dll absent from disk | File where on_disk=False AND referenced_by != [] | ✅ canonical |
| Lateral movement to 172.16.6.12 | net.exe command line + Connected edge to that endpoint | ✅ |
| Defender detections of msedge.exe | AntivirusDetection nodes by threat_name/file_path | ✅ |

**All 7 findings expressible.** The exercise produced two design simplifications:
removing `Process.image_path_is_anomalous` and `Service.name_path_mismatch`
from stored properties (anomaly detection is query-side; see D10).

---

## 7. What is NOT in v1 (deferred to v2 backlog)

The following types appeared during reading of Protocol SIFT's skills but
are deferred — they don't appear in the documented SRL findings:

- `Mutex` (from process handles) — useful for malware family attribution
- `SnapshotVersion` (from VSS) — deleted-but-shadowed evidence
- `NetworkActivity` (from SRUM) — bytes-transferred per process
- `PrefetchEntry` — currently collapsed into Process attributes
- `PowerShellScript` — full script content from EVTX 4104
- `WMISubscription` — fileless persistence mechanism
- `YaraMatch` — pattern-match evidence

Tracked in `docs/SCHEMA_V2_BACKLOG.md`. Adding any to v1 requires a new
DECISIONS.md entry.

---

## 8. Implementation notes (for Day 3)

When implementing this schema in `glaive/graph/schema.py`:

1. Use Pydantic v2 with `model_config = ConfigDict(extra="forbid")` —
   reject unknown fields to catch schema drift early.
2. The base `Node` and `Edge` classes own the universal three. Subclasses
   add type-specific fields.
3. Computed flags (`is_hidden`, `on_disk`, etc.) use `@computed_field`,
   not stored properties.
4. Canonical identity is implemented as a `canonical_key()` method
   returning a tuple — used as the NetworkX node ID.
5. Merge logic lives in a `merge_into(self, other)` method on each subclass.
6. The `disagreements: dict[str, list]` field on nodes accumulates
   conflicting observations across tools.

The Pydantic models will be the literal source of truth — schema doc
and Pydantic must agree. Drift between them is a bug.
