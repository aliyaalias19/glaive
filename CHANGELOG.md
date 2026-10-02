# Changelog

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
