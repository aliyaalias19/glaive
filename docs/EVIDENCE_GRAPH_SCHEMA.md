# Evidence Graph Schema

> **Status:** Skeleton — Day 1. Written in full on Day 2-3 alongside Pydantic implementation.

The evidence graph is the central data structure of GLAIVE. Everything the
agent reasons about is a node or edge. Anything that cannot be expressed as
a node or edge cannot be claimed in a finding.

## Node types (planned)

| Type            | Identifier strategy                      | Key attributes                                      |
|-----------------|------------------------------------------|-----------------------------------------------------|
| Process         | `(host, pid, image_path, start_time)`    | name, command_line, parent_pid, sha256              |
| File            | `(host, full_path)` + optional `sha256`  | mtime, atime, ctime, size, mft_record_number        |
| RegistryKey     | `(host, hive, path)`                     | last_write_time, value_name, value_data             |
| NetworkEndpoint | `(protocol, remote_addr, remote_port)`   | direction, local_port, state                        |
| User            | `(host, sid)`                            | username, domain, type                              |
| Host            | `(hostname | machine_guid)`              | os_version, timezone                                |
| ScheduledTask   | `(host, task_path)`                      | author, action, trigger                             |
| Service         | `(host, service_name)`                   | image_path, start_type, account                     |
| Module          | `(pid, base_address, image_path)`        | size, sha256                                        |
| Driver          | `(host, driver_name)`                    | image_path, loaded_at, sha256                       |

## Edge types (planned)

| Type            | Direction                              | Required attributes                                  |
|-----------------|----------------------------------------|------------------------------------------------------|
| Spawned         | Process → Process                      | timestamp, evidence_hash, derivation                 |
| Loaded          | Process → Module                       | timestamp, evidence_hash, derivation                 |
| Wrote           | Process → File                         | timestamp, evidence_hash, derivation                 |
| Read            | Process → File                         | timestamp, evidence_hash, derivation                 |
| Deleted         | Process → File                         | timestamp, evidence_hash, derivation                 |
| Connected       | Process → NetworkEndpoint              | timestamp, evidence_hash, derivation                 |
| AuthenticatedAs | Process → User                         | timestamp, evidence_hash, logon_type, derivation     |
| Modified        | Process → RegistryKey                  | timestamp, evidence_hash, old_value, new_value       |
| Created         | Process → ScheduledTask / Service      | timestamp, evidence_hash, derivation                 |
| Executed        | User → Process                         | timestamp, evidence_hash, derivation                 |
| Injected        | Process → Process                      | timestamp, evidence_hash, technique, derivation      |
| Persisted       | (Process | File) → (RegKey | Task | Service) | timestamp, evidence_hash, mechanism          |

## Identifier strategy

(Day 2: explain the canonicalization rules — how do we collapse multiple
parsings of "the same process" into one graph node?)

## Provenance contract

Every edge carries an `evidence_hash` pointing at a record in the
content-addressed evidence store, plus a `derivation` field naming the
specific tool execution that produced it. **A finding may reference only
edges whose evidence_hash is resolvable in the store.** This is enforced
at `commit_finding` time, not by convention.
