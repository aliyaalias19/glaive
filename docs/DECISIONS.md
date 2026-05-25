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
