# Limitations

Honesty over perfection. These are the things GLAIVE does not do, or does
imperfectly, as of v0.3.

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

## Accuracy

- The 27 built-in rules generalise poorly (4% right tactic on
  EVTX-ATTACK-SAMPLES); they exist for the demo and as a fallback. Add the
  SigmaHQ rules for real cases.
- The SigmaHQ results are optimistic: those rules are developed and tested
  against the same public datasets GLAIVE is benchmarked on.
- On a clean Windows 10 install the rules raise false alarms (197 built-in,
  360 with SigmaHQ). High-severity findings wait for an analyst, but lower
  ones are committed. See [ACCURACY_REPORT.md](ACCURACY_REPORT.md).
- Rules plus AI has not been measured on public data yet.

## Scale

- A case is held in memory while it is investigated: about 4.4 GB of RAM for
  784,000 events with the SigmaHQ rules. Larger cases need the on-disk store
  planned for v0.4.

## AI agents

- Tests use scripted models and HTTP-level mocks. Real-world quality depends on
  the model you connect.
- A model fooled by text planted in the logs cannot delete rule findings,
  commit invented entities, clear a host or lower a rule finding's confidence,
  but it can still write misleading (cited, grounded) wording and waste an
  analyst's time.
- Default model names were checked against provider documentation in
  October 2026. Providers rename models often; override them with
  `<PROVIDER>_MODEL` if a default stops working.

## Privacy

- Pseudonymisation replaces account names, host names, internal IPs, e-mail
  addresses, domains and SIDs that GLAIVE recognises: from the graph, and by
  pattern (profile paths, DOMAIN\\user, e-mail, SID, private IPv4). A name
  that appears only in free text in an unusual form (a person's name in a
  file name, a password in a command line) can still reach a cloud model. Use
  `GLAIVE_PRIVACY=local-only` when nothing may leave the machine.
- Public IP addresses, file names, hashes, command lines and rule titles are
  sent unchanged: the model needs them to recognise the attack.
- Tokens are numbered per investigation. Vectors stored by a cloud embedder
  were computed on pseudonymised text.

## Search and memory

- Without `GLAIVE_EMBED`, search is keyword-only and does not understand
  synonyms or other languages.
- The default local reranker (jina-reranker-v2-base-multilingual) is licensed
  CC BY-NC 4.0: free for non-commercial use only. Smaller rerankers made the
  results worse on our test, so reranking is off unless you choose one.
- The search index stores node descriptions in `search.sqlite` next to the
  case file; delete it to remove them (it is rebuilt when needed).
- Past-case memory stores claims and indicators in plain text on this computer
  (`GLAIVE_HOME/memory.sqlite`). Remember only cases you are allowed to keep,
  and use `glaive memory forget` when a retention period ends.

## Operational limits

- The web app is built for one analyst on one machine. There are no user
  accounts: the optional `GLAIVE_WEB_TOKEN` is a single shared secret.
- `evidence_root` (MCP server and sessions) restricts which folders can be
  ingested. It is off unless you set it.
- Uploads through the web app are limited to 2 GB by default
  (`GLAIVE_MAX_UPLOAD_MB`).
