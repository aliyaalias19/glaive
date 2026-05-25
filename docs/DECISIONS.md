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
