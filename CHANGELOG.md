# Changelog

## 0.3.0 - 2026-10

### Added
- **Benchmarks on public data** (`glaive bench run`): EVTX-ATTACK-SAMPLES,
  OTRF Security-Datasets and the NextronSystems evtx-baseline goodware logs,
  scored against the datasets' own ATT&CK labels at alert and finding level;
  `glaive bench compare` puts runs side by side (rules alone vs each model).
  CI enforces detection floors on EVTX-ATTACK-SAMPLES.
- **Log-poisoning benchmark** (`glaive bench poisoning`): nine planted prompt
  injections plus a control, and what a model that obeys them could achieve.
- **Privacy**: case data is pseudonymised (USER_1, HOST_2...) before it is
  sent to a cloud model, embedder or reranker, and restored in replies.
  `GLAIVE_PRIVACY=local-only|pseudonymize|off`.
- **Audit trail**: spans for every investigation, agent, model call and tool
  call in `<case>/trace.jsonl` (OpenTelemetry GenAI conventions, no prompt
  text); optional OTLP export (`glaive[otel]`); `glaive trace CASE`.
- **Evidence search (GraphRAG)**: BM25 + optional vectors (local fastembed or
  Ollama, or OpenAI-compatible APIs) fused with RRF, optional reranker; nodes
  are indexed with their neighbours. `glaive search`, `search_evidence` tool
  for agents and MCP, `glaive bench retrieval` (recall@k, MRR).
- **Ask the case** answers from findings and evidence nodes, with checked
  `[F#]` / `[E#]` citations; `glaive ask CASE QUESTION`.
- **Past-case memory** (opt-in, local): `glaive remember`, `glaive memory`,
  indicator overlaps with earlier cases, `recall_past_cases` agent tool.
- ATT&CK tactics on alerts, from a bundled Enterprise ATT&CK v19.2 table
  (old names and revoked IDs such as T1562.001 still resolve).
- Confidence calibration in `glaive eval`.
- Readers for NXLog/Logstash (OTRF) and Winlogbeat JSON; `.tar`, `.tar.gz`
  and `.tgz` evidence archives with the same safety checks as zips.
- `ROADMAP.md`.

### Changed
- Prompt-injection detection also finds text hidden with zero-width
  characters, look-alike letters or Base64 (e.g. `powershell -enc`): 9/9
  planted payloads detected instead of 6/9.
- Findings from a model that clear activity ("no malicious activity", "false
  positive", "the host is clean") wait for analyst approval.
- A Skeptic refutation of a rule finding no longer marks it disputed; it goes
  to an analyst with the Skeptic's argument.
- Sigma rules are pre-filtered per log source and event ID: 2,200 SigmaHQ rules
  run about 2.7x faster with identical results.
- `numpy` is now a dependency (vector search).

### Fixed
- With the web app open in a browser, Ctrl+C did not stop `glaive serve`; a
  second Ctrl+C exited with a traceback.
- The verdict-tampering injection pattern fired on word lists in real Windows
  registry values.

## 0.2.1 - 2026-10

### Fixed
- `glaive demo --serve` crashed with `TypeError: argument of type 'OptionInfo' is not iterable` instead of opening the web app.

## 0.2.0 - 2026-10

### Fixed (found by auditing and running v0.1)
- Fresh installs failed: `mcp>=1.2` pulled mcp 2.x, which renamed `FastMCP`. Now works on 1.x and 2.x.
- CLI crashed on Windows consoles when printing non-ASCII characters.
- The gate accepted claims unrelated to their evidence; claims are now grounded entity by entity.
- Defender event 5001 (real-time protection disabled) was silently dropped.
- Nodes without a source file got placeholder evidence hashes (`fff...`, `000...`); such records are now rejected.
- Orchestrator crashed when a run without a source file preceded one with a file.
- Volatility pstree parent lookup crashed on mixed known/unknown start times.
- `query_graph`: no hard limit, time filters never matched, internals reachable through filters, File paths missing from results, date-like hostnames broke lookups.
- Evidence store: stored copies were writable, and hashing and copying were separate steps.
- Any file could be ingested as a Defender EVTX.
- A damaged EVTX crashed ingestion with the fast reader; it is now skipped with a structured error.
- A bad record in a JSON array export crashed the reader.
- Tests read source files with the system code page and failed on Windows.
- Duplicate `Process` class in `nodes.py`; duplicate `TestFile` class meant 14 tests never ran.
- Registry paths in `\REGISTRY\MACHINE` form were not mapped to `HKLM`.

### Added
- `.glaive` case files (SQLite): graph, findings, evidence manifest, audit log.
- Windows Security / System / Sysmon / PowerShell parsing, cross-log process corroboration.
- Optional Rust EVTX reader (about 1000x faster) with automatic fallback, verified equivalent on 37,364 real events.
- JSON / JSON-Lines event exports; folder and zip ingestion with zip-slip and zip-bomb protection.
- Sigma rule engine, 27 built-in rules, SigmaHQ compatibility; correlation rules; prompt-injection detection.
- Multi-provider model router (Claude, GPT, Gemini, DeepSeek, Qwen, Kimi, GLM, Doubao, OpenRouter, SiliconFlow, Ollama, any OpenAI-compatible server) with fallback, retries, circuit breaker and token budget.
- Agents: rules triage, Hunter, Skeptic, Reporter; human approval of high-severity findings.
- Web app, HTML report, `glaive demo / investigate / serve / report / verify / models / eval / mcp`.
- Web app protection: localhost only by default, token for other addresses, Host and Origin checks against DNS rebinding and cross-site requests, no third-party requests from the page.
- MCP `commit_finding` accepts severity, ATT&CK techniques and a rationale; new tools `case_overview`, `list_alerts`, `get_neighbors`, `get_timeline`, `save_case`.
- Demo case with answer key and accuracy scoring.
- Dockerfile (non-root, token required) and CI on Linux and Windows, Python 3.11 and 3.12, mcp 1.x and 2.x.

### Changed
- The demo uses documentation-only addresses (203.0.113.0/24) and `.example` domains.
- Default Gemini model is `gemini-3.8-flash` (2.5 Flash is limited to existing users).
