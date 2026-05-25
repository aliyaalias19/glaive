# Case Selection — SRL-2018 / rd01

> Status: **DECIDED** on 2026-05-25 (see `DECISIONS.md` D6).

## The case

**Name:** Stark Research Labs (SRL) — 2018 Compromised Enterprise Network
(SANS FOR508 Lab 1.1 scenario)

**Threat actor:** CRIMSON OSPREY (state-level APT)

**Incident:** Initial compromise pivoted into the R&D network via the
`rd01` Remote Desktop Server; lateral movement attempted to `rd02` and
beyond. Defender flagged and terminated multiple masquerading processes,
but the persistence mechanism survived.

## Primary host: rd01

| Aspect | Detail |
|---|---|
| Role | Remote Desktop Server 1, R&D network |
| Network | 172.16.6.0/24 |
| Disk image | `base-rd-01-cdrive.E01` (16.6 GB) |
| Memory dump | `base-rd-02-memory.7z` (~3 GB extracted) [SEE NOTE] |
| Compromise verdict | Active; STUN.exe at PID 1912 |

**NOTE on memory dump naming:** The case template references
`/cases/memory/rd01-memory.img`, but the public starter data contains
`base-rd-02-memory.7z`. Verify on download whether rd-02-memory.7z is
the memory image of rd01 (host) or rd02 (host). If naming is ambiguous,
download both `base-rd-02-memory.7z` and `base-rd-03-memory.7z` and
match by hostname inside the image.

## Documented ground truth (from Protocol SIFT case template)

These are the canonical findings GLAIVE must reproduce.

### Malware artifacts
- **STUN.exe** — `C:\Windows\System32\STUN.exe`, PID 1912,
  parent svchost.exe PID 1244
- **msedge.exe (7 instances)** — spawned from STUN.exe + explorer.exe;
  classified Trojan:Win32/PowerRunner.A
- **pssdnsvc.exe** — `C:\Windows\`, name/path mismatch from PsShutdown service
- **atmfd.dll** — registered in Autoruns but absent from filesystem

### Attacker activity
- Execution chain: scheduled task → STUN.exe → svchost.exe → taskhostw.exe
- Lateral movement: `net use H: \\172.16.6.12\c$\Users` from net.exe PID 9128
- Evasion: msedge.exe masquerading; Defender repeatedly terminating

### Timeline anchors (UTC)
- 2023-01-24 — Incident declared
- 2023-01-25 14:52:04 — Lateral movement command
- 2023-01-25 14:56:42–15:04:43 — msedge.exe PIDs spawning
- 2023-01-25 15:00:56 — msedge.exe PID 2524 active at memory capture time
- 2023-01-29 12:23:16 — Kansa post-intrusion collection

## Source

SANS starter case data (Devpost Resources page):
`https://sansorg.egnyte.com/fl/HhH7crTYT4JK`
→ `HACKATHON-2026/Compromised APT.../SRL-2018-Compromised Enterprise Network/`

Shared by Rob T. Lee (SANS Chief AI Officer), accessible until 2026-06-17.

## Download plan

**Not yet downloaded.** Defer until Day 4 (ingestion work begins).

Required (~20 GB total):
- `base-rd-01-cdrive.E01` (16.6 GB)
- `base-rd-02-memory.7z` (~932 MB compressed) — verify hostname after extract
- `base-rd-03-memory.7z` (~933 MB compressed) — backup in case above is rd02 not rd01

Stretch (only if Week 3 has spare time, per D6):
- `base-dc-memory.7z` (808 MB) — for cross-host correlation demo

## Why this case beats alternatives

| Alternative | Why we didn't pick it |
|---|---|
| CyberDefenders #c56 (CyberCorp) | Excellent case, but not in SANS starter data — judges may not have it |
| SRL-2015 case | Older, four hosts but no documented Protocol SIFT case template |
| Multi-host SRL-2018 | Violates D4 (depth over breadth); too much surface to nail in 3 weeks |
