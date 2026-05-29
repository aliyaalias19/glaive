# Strategic Decisions Log

Decisions made under conviction get forgotten under stress. This file
captures the *why* behind GLAIVE's design choices so future-Aliya can
re-read them at hour 18 of day 14 and not panic.

---

## D1 — 2026-05-25 — Extend Protocol SIFT, do not replace it

**Decision:** GLAIVE is built as an extension layer on top of Protocol SIFT,
not as a standalone competitor. We add a new skill file, a small MCP server,
and an ingestion layer. We do not modify Protocol SIFT's baseline CLAUDE.md
or its 5 skills.

**Why:** The hackathon rules require it ("Entrants must submit a working
software application that **extends Protocol SIFT's autonomous incident
response capability**"). Replacing it would fail Stage One pass/fail. Also,
extending is less work and shows engineering humility, which judges value.

---

## D2 — 2026-05-25 — Graph-as-critic, not LLM-as-critic

**Decision:** No second LLM as a "Critic" agent. The critic is the graph
itself: `commit_finding` rejects claims that don't trace to graph paths.

**Why:** Protocol SIFT's CLAUDE.md explicitly forbids the agent from asking
the human during a task ("Run every workflow fully autonomously
start-to-finish. No check-ins, no confirmations."). A second LLM critic adds
cost, latency, and another hallucination surface. Architectural rejection
via graph paths is both cheaper and stronger.

---

## D3 — 2026-05-25 — Five MCP tools, not fifty

**Decision:** GLAIVE exposes 5 MCP tools (ingest, query, verify, commit,
flag_unresolvable). Protocol SIFT's existing bash-driven SIFT tools are
left unchanged.

**Why:** A small reasoning surface is harder to bypass. The judging
criterion "Constraint Implementation" explicitly distinguishes architectural
constraints from prompt-based ones; fewer tools means fewer architectural
edges to defend.

---

## D4 — 2026-05-25 — One deep case beats three shallow ones

**Decision:** Solve one case completely against ground truth, rather than
demonstrate breadth across three. (Original plan was three cases.)

**Why:** The judging rubric explicitly says *"Depth on fewer types beats
shallow coverage of many."* Steve Anson's reference submission (Valhuntir)
will likely cover broad surface area; we compete on depth and rigor.

---

## D5 — 2026-05-25 — WSL2 Ubuntu, not VirtualBox VM

**Decision:** Develop on WSL2 Ubuntu 22.04 with SIFT installed via cast
(SANS Option 2B), not on the SIFT VM appliance (Option 1).

**Why:** 15.9 GB host RAM is tight for a static VM allocation. WSL2 shares
RAM dynamically with Windows, boots in 2 seconds vs 60 for VMs, and is an
officially supported SIFT install method. Iteration speed compounds over a
3-week sprint.

---
## D6 — 2026-05-25 — Case: SRL-2018 (rd01), single host depth

**Decision:** Use the SRL-2018 Compromised Enterprise Network case as our single
ground-truth case. Within it, focus on the `rd01` host (Remote Desktop Server 1)
— the documented primary compromise host from the FOR508 Lab 1.1 scenario.

**Why:**
- Protocol SIFT's `~/.claude/case-templates/CLAUDE.md` is *written for this exact case*.
  It ships with IOCs, a timeline, and tool invocations specific to SRL.
- SANS published the evidence to all hackathon participants via the Devpost
  starter case data link (`https://sansorg.egnyte.com/fl/HhH7crTYT4JK`),
  shared by Rob T. Lee. Judges have it.
- Single-host depth fits the rubric's explicit guidance: *"Depth on fewer types
  beats shallow coverage of many."* (Section 6, judging criteria.)
- rd01 has both disk image (`base-rd-01-cdrive.E01`, 16.6 GB) and memory dump
  (`base-rd-02-memory.7z`, ~3 GB extracted). Full multi-source coverage on one host.
- The case has documented ground truth (IOCs in the case template: STUN.exe,
  msedge.exe masquerading, pssdnsvc.exe, atmfd.dll, lateral movement via
  `net use H: \\172.16.6.12\c$\Users`). We can measure precision/recall against it.

**Scope refined (see D9):** Primary submission is rd01 depth. In Week 3 we
add a single cross-host correlation finding using dc01 memory — not a
multi-host platform, but a demonstration that the graph schema supports
multi-host without that being the headline feature. Cross-host correlation
is committed Week 3 scope, not a maybe.

---

## D7 — 2026-05-25 — Output convention: `analysis/exports/reports/`

**Decision:** GLAIVE writes outputs to `./analysis/`, `./exports/`, `./reports/`
inside each case directory, matching Protocol SIFT's convention. We do not
invent our own output layout (originally planned: `runs/case1/`).

**Why:** Protocol SIFT's CLAUDE.md states the convention three times. The case
template enforces it. Judges familiar with Protocol SIFT will look for outputs
there. Matching the convention signals we read the platform's docs.

**Practical effect:** The CLI command becomes
`glaive investigate /cases/srl/` (operating on the case directory in-place)
rather than `glaive investigate evidence/ --output runs/case1/`.

---

## D8 — 2026-05-25 — Schema design tested against the SRL findings

**Decision:** The evidence graph schema (designed in `docs/EVIDENCE_GRAPH_SCHEMA.md`)
must be tested by attempting to represent every documented finding from the SRL
case template *before* implementation begins. If the schema cannot express a
finding, the schema is incomplete.

**Why:** Reading the case template revealed schema gaps we'd otherwise have
discovered mid-implementation:
- File nodes need an `exists` property (for findings like "atmfd.dll listed
  in Autoruns but absent from filesystem").
- A `References` edge type from RegistryKey/Autoruns to File is required.
- Node-level anomaly properties matter, not just graph edges (e.g.,
  "msedge.exe masquerading" is a property check, not a relationship).
- Multi-host scoping requires `Host` as a top-level scope; `(host, pid)`
  identifier pairs prevent collision.

The "schema fits findings" exercise is the design's primary correctness check.

---
## D9 — 2026-05-25 — Judging scope: 2 Very Strong + 4 Strong

**Decision:** Build for "2 Very Strong + 4 Strong" coverage of the six
judging criteria (Section 6 of the rules). Not "6 Very Strong" (unrealistic
for solo 3-week effort against Valhuntir-scale submissions). Not "2 Strong
+ 4 mixed" (leaves exploitable soft spots).

**Target scorecard:**

| Criterion | Target | What earns it |
|---|---|---|
| 1. Autonomous Execution Quality | Strong | Three-tier self-correction (tool failure / graph rejection / self-uncertainty), all logged with timestamps and token usage |
| 2. IR Accuracy | **Very Strong** | Graph-grounded findings; multi-source `confirmed_by` corroboration; honest accuracy report with precision/recall/hallucination count against SRL ground truth |
| 3. Breadth and Depth | Strong | rd01 deep coverage (all 3 evidence types, all documented SRL findings) + one cross-host correlation finding from dc01 memory |
| 4. Constraint Implementation | **Very Strong** | Architectural commit gate (not prompt-based); 5 bypass tests with documented architectural defense reasoning |
| 5. Audit Trail Quality | Strong | Every finding → graph path → `evidence_hash` → byte offset, demonstrated in <15s of demo |
| 6. Usability and Documentation | Strong | One-command install + 3-minute fresh-install video; `docs/EXTENDING.md`; architecture poster (PNG); CI passing in public repo |

**Why this scorecard and not "6 Very Strong":**

Hackathon scoring is comparative. "Very Strong" means meaningfully better
than the field on that criterion. Two criteria are structurally hard to
dominate as a solo 3-week effort:

- **Breadth & Depth** — Valhuntir-style platforms cover broad surface area
  by virtue of being multi-month team projects with many tool integrations.
  Trying to match breadth costs us depth on bypass tests. The rule explicitly
  says *"depth on fewer types beats shallow coverage of many"* — we trust
  that rule and play to depth instead.
- **Usability & Documentation** — Web portals with polished UIs are
  expensive in time. Our SIFT-native terminal interface is appropriate to
  the target environment; we earn "Strong" on usability by being deployable
  and well-documented, not by being shiny.

The two **Very Strong** criteria — IR Accuracy and Constraint Implementation
— map directly to the hackathon's *stated* theme:
*"Protocol SIFT works. It also hallucinates more than we'd like. That's
exactly why this hackathon exists."* — Rob T. Lee, SANS Chief AI Officer.

We win on the theme, hold on the rest, and accept that no solo project
can outshine multi-month platforms on every axis.

**What this commits us to in calendar time:**

| Week 3 day | Task |
|---|---|
| Day 17 | Cross-host correlation: download dc01 memory, parse, populate Host node |
| Day 17-18 | EXTENDING.md and CI workflow setup |
| Day 19 | 3-minute fresh-install video + architecture poster PNG |
| Day 20 | Main 5-minute demo video |

If any of these slip, the cuts come from the Strong upgrades (not from the
Very Strong baseline).

---
## D10 — 2026-05-25 — Anomalies are query-side; query catalog is v1 scope

**Decision:** Anomaly detection (e.g., "process is masquerading," "service
name doesn't match its image path") lives in *queries*, not in stored
node properties. A small **query catalog** under `glaive/queries/` is v1
scope.

**Why:**

While walking through the SRL findings → schema mapping (Section 6 of
`docs/EVIDENCE_GRAPH_SCHEMA.md`), two originally-planned stored properties
were identified as judgments rather than observations:

- `Process.image_path_is_anomalous` — answers "is this masquerading?"
- `Service.name_path_mismatch` — answers "does the service name match its binary?"

Both encode *interpretation*, not *evidence*. The schema's job is to store
what tools observed; interpretation belongs in a separate layer that can
evolve without schema changes.

**Practical effect:**

- Drop both fields from the schema (already reflected in v1 doc).
- Add `glaive/queries/` — a module of named, parameterized queries the
  agent can invoke by name (e.g., `find_masquerading_processes(host)`).
- The query catalog itself is small (~10-15 queries), each ~10-30 lines
  of NetworkX traversal. Estimated build cost: ~6-8 hours in Week 2.

**Why include in v1, not defer:**

Without a query catalog, the agent must construct anomaly checks from
scratch every run. That's:
- Slower (LLM reconstructs the same logic repeatedly)
- Inconsistent (different runs may apply different criteria for "masquerading")
- Harder to audit (no canonical definition of each anomaly type)

The catalog makes anomalies *named, versioned, and testable* — directly
supporting our Audit Trail (Criterion 5) and IR Accuracy (Criterion 2)
positions.

**Trade-off accepted:** Slightly more Week 2 work for a meaningfully
stronger demonstration of architectural reasoning quality.

---


## I1 — 2026-05-27 — Evidence store location: `./analysis/evidence_store/`

**Decision:** The content-addressed evidence store lives at `./analysis/evidence_store/` inside the working directory, not in a system-wide location, a temp directory, or a configurable global path.

**Why:** Two reasons. First, this matches Protocol SIFT's `./analysis/` convention (D7) — judges familiar with SIFT immediately recognize the layout. Second, scoping the store to the case directory means `rm -rf` cleans up cleanly between investigations without touching source evidence, and one machine can host multiple parallel case directories without collisions. Configurable paths and system-wide locations both create the kind of "what state is on this machine?" confusion that ruins reproducibility.

---

## I2 — 2026-05-27 — Filename convention: `<sha256>.<original_extension>`

**Decision:** Ingested evidence is stored at `./analysis/evidence_store/<sha256_hex>.<extension>`. The hash is the lookup key; the extension is cosmetic.

**Why:** The hash *is* the identity. Two files with identical bytes get one stored copy, regardless of original filename. The extension is preserved so a human (or a tool that needs file-type detection) can identify the format at a glance — e.g. seeing `0e43...evtx` immediately tells you it's an EVTX, while a bare hash would force a `file` command. The manifest preserves the original filename for the audit trail; the on-disk filename is for human grokking.

---

## I3 — 2026-05-27 — Manifest: `manifest.json` with atomic writes

**Decision:** The evidence store maintains a JSON manifest mapping hash → metadata (original filename, size, ingest timestamp). Writes are atomic via the write-to-temp-then-rename pattern.

**Why:** Without a manifest, the on-disk filenames are opaque hashes — you can't answer "what was the original name?" without parsing the file. The manifest is the human-readable index. Atomic writes matter because forensic ingestion is often *long* (parsing a 16 GB memory dump can take an hour). If the process dies mid-write, a non-atomic manifest could end up half-written and corrupt — losing the entire ingest history. Write-temp-then-rename guarantees the manifest is always either the old version or the new version, never a partial one.

---

## I4 — 2026-05-27 — Immutable store with idempotent ingest

**Decision:** Once a hash is stored, the file is never overwritten. Re-ingesting the same file returns the existing hash silently (no error, no copy).

**Why:** Two properties this gives us. First, **forensic chain-of-custody integrity** — once evidence enters the store, its bytes never change. A judge can re-hash the stored file at any time and verify it matches the manifest. Second, **idempotent pipelines** — re-running the full ingestion (which we do constantly during development) doesn't duplicate files or pollute the store. The cost is zero (idempotent operations are easier to reason about than "what if I run this twice?"), and the upside is real provenance.

---


## P1 — 2026-05-27 — Parser architecture: class-based, store-bound

**Decision:** Every parser is a class that inherits from `Parser` and takes an `EvidenceStore` in its `__init__`. The interface is one method, `parse(source) -> ParseResult`. Parsers never touch a graph directly.

**Why:** Clean separation of concerns. Parsers do one thing: extract typed nodes and edges from a source. The orchestrator decides where those go. This means we can unit-test parsers in isolation (no graph needed), and the same parser output can be fed to multiple destinations (graph, JSON dump, replay log) without changing parser code. Class-based over function-based because parsers need to carry the store reference and may eventually accumulate state (caches, statistics) — and discovering you need state in a function-based API is a painful refactor.

---

## P2 — 2026-05-27 — Defer binary-format parsing to a separate adapter layer

**Decision:** For Day 4, parsers accept pre-parsed input (Python dicts) only. Binary file parsing (binary EVTX → dicts, binary memory dump → dicts) lives in a separate adapter module. Passing a `Path` to `parser.parse()` explicitly raises `NotImplementedError` until the binary layer is added in Day 5+.

**Why:** Two-layer architecture has clear ownership: parsers know schemas, adapters know binary formats. Mixing the two would mean every parser fights both EVTX XML edge cases *and* schema mapping, which is twice the bug surface. The explicit `NotImplementedError` is also a contract — it tells the next person "this layer doesn't do binary; if you want that, write the adapter." Cleaner than silently failing on unexpected input.

---

## P3 — 2026-05-27 — Defender: only the 5 detection event IDs

**Decision:** `DefenderEvtxParser` accepts only event IDs in `SUPPORTED_EVENT_IDS = {1116, 1117, 1118, 1119, 5001}`. All other event IDs are silently skipped and counted.

**Why:** From the schema (Section 2.10), `AntivirusDetection` is earned from exactly these five events. Other Defender events (1000 startup, 5007 config change, 1150/1151 telemetry) are *not* detection events and don't map to our schema. Accepting them would either pollute the graph with non-detection nodes or force us to invent new node types prematurely. The skip-and-count pattern gives the orchestrator visibility into what was filtered, so we can verify our supported-IDs assumption against real data. (When we ran against real Defender.evtx, 15,901 of 15,911 events were filtered correctly — that's the assumption confirmed.)

---

## P4 — 2026-05-28 — Volatility: one parser, three plugin inputs

**Decision:** `VolatilityProcessParser` takes input from `psscan`, `pslist`, and `pstree` in a single dict, produces a coherent set of `Process` nodes and `Spawned` edges from all three. We do *not* write three separate parsers.

**Why:** The three plugins describe the *same* processes from different angles. Separate parsers would produce three sets of `Process` nodes that need post-processing to merge — a worse architecture that loses the `observed_by` semantics. A unified parser accumulates `observed_by` naturally as it processes each plugin's input, and produces `Spawned` edges only when `pstree` is provided (the optional input pattern). One parser, one ParseResult, one truth.

---

## P5 — 2026-05-28 — Process dict schema with `_`-prefixed orchestrator fields

**Decision:** Process input dicts use underscore-prefixed keys (`_evidence_hash`, `_derivation`, `_host_hostname`) for fields injected by the orchestrator, distinct from the schema fields (`pid`, `name`, `start_time`, etc.) that come from the source.

**Why:** Clear separation between *parser data* (what the tool extracted) and *infrastructure metadata* (what the orchestrator wrapped around it). The `_` prefix signals "not from the source, injected by infrastructure" — anyone reading the dict can tell at a glance which fields are tool output vs. machinery. This convention generalizes to every parser; we use the same shape for `DefenderEvtxParser` and any future adapter.

---

## P6 — 2026-05-28 — Cross-plugin merge uses the schema's own `merge_into`

**Decision:** When the same process appears in `psscan` and `pslist`, the parser calls `existing.merge_into(new)` — using the merge logic defined on the `Process` Pydantic model itself, not reimplementing it.

**Why:** Single source of truth. The schema already knows how to merge two observations of the same process — it lives in `Node.merge_into()` (Day 3 work). If the parser had its own merge logic, we'd have two places to maintain the same rules, and they'd drift. By delegating to the schema's method, the parser stays thin and any future merge rule changes (e.g., new fields that need union semantics) update automatically.

---

## P7 — 2026-05-28 — pstree parent lookup uses wildcard-on-start-time

**Decision:** When building `Spawned` edges from pstree, the parent process is looked up by `(host, parent_pid)` with start_time wildcarded — we take the most recent process matching those that started *before* the child.

**Why:** Volatility's pstree output gives `(parent_pid, child_pid, child_start_time)` triples — but it does NOT give us the parent's start_time. Our `Process` canonical_key includes start_time, so an exact lookup is impossible. The "most recent parent before child" heuristic works because PID recycling within a single memory dump is rare (typically requires the system running for weeks). If multiple candidates do exist, we take the latest valid one. This is a known fragility (documented in LIMITATIONS.md) but acceptable for v1 — and the alternative (skipping all pstree edges) would lose the most important process-relationship signal.

---

## P8 — 2026-05-28 — Malformed input is skipped, not raised

**Decision:** Parsers catch malformed input at the per-record level (missing required fields, bad timestamps, type errors). Bad records are skipped silently; counts are tracked in the ParseResult. A single bad record does not abort parsing of the other 15,910.

**Why:** Forensic data is messy. A 16 MB EVTX file may contain partial records from slack space, corrupted timestamps, unexpected field combinations. If one bad record raised an exception, the parser would crash before delivering the 15,910 good ones — catastrophic for ingestion. The defensive-skip approach delivers what's parseable and surfaces the skip count so the orchestrator (and the agent) know what was lost. This is consistent with how Volatility, Plaso, and other production forensic tools handle malformed input.

---

## O1 — 2026-05-28 — Orchestrator: class-based, accumulates state

**Decision:** `Orchestrator(graph, store)` is a class that holds the graph and store, accumulates ingest reports across runs, and exposes a `run(parser, source_path, parse_input)` method.

**Why:** An investigation typically runs *multiple* parsers against the same case (Defender + Volatility + MFT + registry). Class-based orchestrators naturally accumulate ingest reports across parser runs, give us a single `summary()` view of the investigation's data lineage, and let us attach lifecycle hooks (logging, agent context, telemetry) without changing call sites. A functional `ingest(graph, store, parser, source)` would require passing graph/store to every call and managing report accumulation externally — more friction, less natural API.

---

## O2 — 2026-05-28 — Orchestrator hashes files; parsers receive hash via input

**Decision:** When `Orchestrator.run()` is called with a `source_path`, the orchestrator hashes the file via `store.ingest()` *before* parsing. The resulting `evidence_hash` is injected into the parser's input via the `_evidence_hash` convention (P5), so every node and edge the parser produces carries it.

**Why:** Hashing is *infrastructure*, not parser logic. Parsers should stay testable with synthetic input — no filesystem, no SHA-256 computation. Putting the hash step in the orchestrator means parsers are pure data transformations, and the orchestrator owns the chain-of-custody linkage. Bonus: one file parsed by *multiple* parsers (e.g., a memory dump → Volatility + future plugins) gets hashed once, not N times.

---

## E1 — 2026-05-28 — EVTX adapter: generator, not list

**Decision:** `iter_evtx_events(path)` is a generator that yields one event dict at a time, not a function that returns a `list[dict]`.

**Why:** Real EVTX files can contain hundreds of thousands of records. Loading them all into memory simultaneously is wasteful for large files (a Security.evtx from a production server can be 1 GB+). Generator semantics let the caller consume records one at a time, stop early if it wants, or batch them however suits. It also pairs naturally with our parsers, which accept any iterable. The caller can always call `list()` to materialize if needed — but that's a *choice*, not forced.

---

## E2 — 2026-05-28 — One adapter file per binary format

**Decision:** `glaive/ingestion/evtx_adapter.py` handles all EVTX-based sources (Defender, Security, System, PowerShell logs share this adapter). Other formats — CSV from EZ Tools, JSON from Volatility's raw output — get their own adapter files when needed.

**Why:** The binary format is the constant; the *content schema* varies. All EVTX files have the same `<System><EventID/></System><EventData><Data Name="..."/></EventData>` structure. Putting one EVTX parser per source (`security_adapter.py`, `defender_adapter.py`) would duplicate the python-evtx + lxml plumbing N times. One adapter, multiple downstream parsers consuming its uniform output — the canonical separation.

---

## E3 — 2026-05-28 — Path normalization happens in the adapter, not the parser

**Decision:** Defender's quirky path format (`file:_C:\Users\...zip` or `webfile:_C:\...zip|https://...;...`) is cleaned in `_clean_defender_path()` *inside* the EVTX adapter, before the dict reaches the parser.

**Why:** Adapters know binary-format quirks; parsers should see *clean* data. If the parser had to know about `file:_` prefixes, it would be tangled with EVTX-specific concerns — and when we add another source emitting similar paths, we'd duplicate the cleaning logic. Pushing normalization down to the adapter keeps parsers focused on schema mapping. The cost is small (one small function in the adapter); the benefit is parsers stay reusable across different binary layers.

---

## E4 — 2026-05-28 — Malformed records are skipped, count tracked

**Decision:** The adapter catches `etree.XMLSyntaxError`, `ValueError`, and `AttributeError` per record. Bad records increment `EvtxReadStats.records_skipped_malformed` and yield nothing; good records continue.

**Why:** Same rationale as P8 — forensic data is messy. The adapter is broader than the parser in what it catches (XML syntax errors, not just schema violations), because EVTX-from-slack-space can be structurally broken in ways our parsers don't know about. Catching at the adapter layer means parsers see only structurally-valid records, and the adapter's `EvtxReadStats` surfaces how much was lost. (When we ran against real Defender.evtx: 0 malformed records out of 15,911. The defensive code paid for itself in confidence, not in actually running.)

---

## M1 — 2026-05-29 — Five MCP tools, not fifty

**Decision:** The v1 MCP server exposes exactly 5 tools: `ingest_artifact`, `query_graph`, `get_node_provenance`, `commit_finding`, `list_evidence`. No `delete_node`, no `run_volatility`, no raw bash escape hatch.

**Why:** This was D3 at strategic level; M1 is the implementation commitment. Each tool earns its place: 2 ingestion, 2 query/read, 1 gate (commit). The omissions matter as much as the inclusions. No `delete_node` because the graph is append-only via merging — deletion would let an agent erase inconvenient evidence. No `run_volatility` because parser plumbing should be invisible to the agent (M6). No raw bash because the entire thesis is that the agent operates through a *typed* boundary; a bash escape would defeat it. Small surface area = stronger architectural argument and a smaller bypass-test target.

---

## M2 — 2026-05-29 — Stateful server, one session per server lifetime

**Decision:** The MCP server holds one `GlaiveSession` for the duration of the connection. Restart server = fresh session. Tools capture the session via closure (M4). No `session_id` parameter on tools; no concurrent multi-investigation support.

**Why:** Forensic investigators work one case at a time. Adding multi-session support to v1 would require session IDs in every tool argument, a session manager, and authorization logic — none of which the hackathon judges will exercise. The single-session model maps directly to "one Claude Code conversation = one investigation," which is also how the demo video will work. We can add multi-session in Week 2 if needed; right now it would be premature complexity.

---

## M3 — 2026-05-29 — The commit gate enforces three things

**Decision:** `commit_finding` enforces, in this order: (1) every supporting_node_key resolves to a real graph node; (2) the agent's `confidence_hint` is checked against graph-derived confidence and downgraded if unsupported; (3) findings are stored in a typed `Finding` Pydantic structure, not free text.

**Why:** This is the entire thesis as code. Without (1), the agent can fabricate keys and commit findings about evidence that doesn't exist (hallucination). Without (2), the agent can claim "confirmed" for any finding regardless of corroboration (overclaim). Without (3), findings become unstructured prose impossible to audit. Together, the three enforcements make hallucination *architecturally* impossible — not just discouraged by prompting. This is the answer to Criterion 4 (Constraint Implementation): "show your security boundaries and prove they were tested for bypass."

---

## M4 — 2026-05-29 — Closure factory for tool state

**Decision:** Tools are defined inside `build_server(session)` as closures that capture the session. Per-test isolation is achieved by calling `build_server` with a fresh session.

**Why:** Three alternatives considered (globals, lifespan context, closures). Globals leak state across tests — unacceptable. Lifespan is more "correct" MCP-idiomatic but adds moving parts that don't pay for themselves at v1 scale. Closures are explicit (you can see exactly what each tool captures), test-isolated (each `build_server` call is independent), and require zero MCP framework knowledge to understand. The cost is that tools aren't importable as top-level functions, but we route around that by putting the *logic* in `tools.py` as module-level helpers and making the closures thin dispatchers.

---

## M5 — 2026-05-29 — Explicit `source_type` enum on ingest, not auto-detection

**Decision:** `ingest_artifact(path, source_type)` requires the agent to declare what kind of evidence it's ingesting. `source_type` is a known enum (currently `"defender_evtx"`; more added in Week 2). Auto-detection by extension or magic bytes is *not* used.

**Why:** A `.evtx` file could be Security, System, PowerShell, Defender, or any of dozens of providers — each with different schemas. Auto-detection by extension would silently mis-parse. Auto-detection by magic bytes is unreliable across Windows versions. Explicit declaration makes the agent's intent *auditable* — the chain of custody now includes "agent declared this was a Defender log," not "the system guessed." Wrong-type declarations get clear error messages that the agent can self-correct from.

---

## M6 — 2026-05-29 — Tools hide internal plumbing from the agent

**Decision:** The agent calls `ingest_artifact("path", "defender_evtx")` and never knows that internally we call `iter_evtx_events()` → `DefenderEvtxParser` → `Orchestrator.run()`. Tool documentation describes *what* the tool does (in agent-relevant terms), not *how* (the framework chain).

**Why:** Two reasons. First, simpler agent mental model — the agent reasons about "evidence kinds," not Python module names. Second, swappability — when we add support for compressed EVTX, change adapters, or refactor the orchestrator, the agent's tool calls don't change. The MCP boundary is the *contract* between agent and pipeline; everything below it is implementation detail.

---

## M7 — 2026-05-29 — Path safety: basic v1 guard, full sandboxing deferred

**Decision:** `do_ingest_artifact` resolves the path, rejects non-existent files, and rejects directories. It does *not* yet enforce an allowlist of permitted evidence directories (e.g. forbid `/etc/passwd` or `~/secrets/`). Full sandboxing is a Week 2 bypass-hardening task.

**Why:** Honest. v1 needs basic existence/type checks to fail gracefully on the common cases (typo'd paths, directories instead of files). Full sandboxing — restricting reads to a permitted evidence root — is real security work that deserves its own design pass. Doing it half-right in v1 would create a false sense of safety. We document the limitation in `LIMITATIONS.md`, target it specifically in the Week 2 bypass test suite, and harden it then. Premature hardening with bugs would be worse than honest gaps.

---

## M8 — 2026-05-29 — Declarative filters, no agent-supplied code

**Decision:** `query_graph` accepts filters as structured dicts (`{"field": "...", "op": "...", "value": ...}`), not as Python predicates or strings to be eval'd. Supported ops are a closed set: `eq`, `contains`, `gt`, `lt`, `exists`.

**Why:** This is the equivalent of M3 for the read path. If we accepted Python predicates from the agent, we'd need an `eval` somewhere — at which point the architectural-constraint story collapses (the agent could write arbitrary code). The closed declarative form is *expressive enough* for forensic queries (every SRL finding we promised can be expressed with these 5 ops) and *unbypassable* (no execution path). Bonus: declarative filters can be logged, audited, and replayed without ambiguity.

---

## M9 — 2026-05-29 — Query results are node summaries, not full Pydantic objects

**Decision:** `query_graph` returns a list of compact JSON-safe summaries — `canonical_key` + `node_type` + `evidence_hash` + a handful of common display fields — not full Pydantic models. Results are capped at `limit` (default 100).

**Why:** Two concerns. First, *context budget* — full Process or AntivirusDetection nodes are large; flooding the agent's context with 100 of them wastes tokens that should go to reasoning. Summaries are ~10× smaller. Second, *resource bounds* — the default 100 limit is the answer to the "resource exhaustion" bypass test. A query that would return 10,000 nodes truncates with `truncated: true`, so the agent learns to refine its filters rather than receive a DoS-sized payload.

---

## M10 — 2026-05-29 — Datetime round-trip via `_coerce_key`

**Decision:** `canonical_key` elements containing datetimes get serialized to ISO 8601 strings when returned to the agent (JSON has no datetime type). When the agent passes a key back (to `commit_finding` or `get_node_provenance`), `_coerce_key()` parses any ISO-string elements back to datetimes before graph lookup.

**Why:** Discovered while wiring `query_graph` — the canonical_key for AntivirusDetection has a datetime element, and `json.dumps` raised on it. Quick fix was to isoformat datetimes on the way out. But that created the *round-trip problem*: a string in, a datetime in the graph, no match. The `_coerce_key` helper resolves it by parsing any element that successfully passes `datetime.fromisoformat()` back to datetime; everything else passes through unchanged. Threat names, hostnames, hashes — none of those accidentally parse as datetimes, so the coercion is safe. This pattern will be needed for any tool that takes a canonical_key as input, so it lives in shared infrastructure.

---

## M11 — 2026-05-29 — Confidence downgrade commits, doesn't block

**Decision:** When `commit_finding` finds the agent's `confidence_hint` is higher than the graph evidence supports, it *commits* the finding at the (lower) graph-derived confidence and returns `decision: "downgraded_confidence"`. It does not reject.

**Why:** The finding is *real and supported* — it just isn't as certain as the agent claimed. Blocking it would lose a true finding over a confidence quibble. Honest downgrade preserves the finding while being transparent: the report shows `confidence: "suspected"` even though the agent wanted `"confirmed"`, and the decision response tells the agent what happened so it can self-correct in future calls. This is also a great demo moment — "watch the agent claim confirmed, watch the gate downgrade it, watch the report reflect honesty over confidence." That sequence is the thesis in action.

---
