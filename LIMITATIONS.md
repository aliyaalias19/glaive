# Limitations

Honesty over perfection. These are the things GLAIVE does not do, or does
imperfectly, as of v0.2.

## Evidence it cannot read yet

- **Windows event logs only.** EVTX (Security, System, Sysmon, PowerShell,
  Microsoft Defender) and JSON / JSON-Lines exports of them. Other files in an
  evidence folder are hashed into the store for chain of custody but not parsed.
- **No memory, disk or registry-hive analysis in the pipeline.** A Volatility
  pstree parser exists in `glaive/ingestion/volatility.py` from v0.1, but it is
  not wired into `glaive investigate`. Disk images, registry hives, Linux,
  macOS, cloud audit logs and network captures are on the roadmap.
- **PowerShell 4104 events are not linked to their process** unless the export
  carries the process id: the readers do not keep the `Execution` element.

## What the gate can and cannot catch

- It checks **concrete entities**: IP addresses, file paths, hashes, domains,
  account and threat names. A claim can still overstate what the evidence
  means using ordinary words ("the attacker *exfiltrated* data" when the
  evidence only shows a connection). The Skeptic agent and analyst approval of
  high-severity findings exist for this.
- Confidence comes from how many independent sources corroborate the cited
  evidence. Two logs that are both wrong in the same way still count as two.
- No attribution ("this was APT-X") and no legal conclusions.

## Heuristics that can be wrong

- **Process identity** across logs uses (host, PID, start time truncated to the
  second). Very fast PID reuse within one second can merge two processes.
- Events that only carry a PID (network, file, registry) are attached to the
  most recent process with that PID that started before them.
- The Volatility pstree parser picks the most recent parent started before the
  child, because pstree output does not include the parent's start time.
- **Correlation thresholds** (5 failed logons within 10 minutes; tampering then
  a high alert within 2 hours) are fixed defaults, not tuned per environment.
- At most 250 alerts per rule are kept, so a very noisy community rule cannot
  flood the graph; the summary reports how many were suppressed.

## Sigma support

About 90% of SigmaHQ's Windows rules load (2,168 of 2,410 when measured).
Rules using aggregations (`| count()`), `base64` / `base64offset` / `utf16`
modifiers, `near`, or log sources GLAIVE does not parse are skipped and
reported, never evaluated incorrectly.

## AI agents

- Tests use scripted models and HTTP-level mocks. Real-world quality depends on
  the model you connect.
- Default model names were checked against provider documentation in
  October 2026. Providers rename models often; override them with
  `<PROVIDER>_MODEL` if a default stops working.

## Operational limits

- The web app is built for one analyst on one machine. There are no user
  accounts: the optional `GLAIVE_WEB_TOKEN` is a single shared secret.
- `evidence_root` (MCP server and sessions) restricts which folders can be
  ingested. It is off unless you set it.
- Uploads through the web app are limited to 2 GB by default
  (`GLAIVE_MAX_UPLOAD_MB`).
