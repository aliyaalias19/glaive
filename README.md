# GLAIVE
**Graph-Linked Adversarial Investigation & Verification Engine**

> Protocol SIFT lets Claude Code run forensic tools and asks it nicely not to
> hallucinate. GLAIVE makes hallucination *architecturally impossible* by
> forcing every finding to correspond to a path in a typed evidence graph.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: SIFT](https://img.shields.io/badge/Platform-SANS%20SIFT-blue.svg)](https://www.sans.org/tools/sift-workstation/)
[![Extends: Protocol SIFT](https://img.shields.io/badge/Extends-Protocol%20SIFT-green.svg)](https://github.com/teamdfir/protocol-sift)

GLAIVE is a submission to the **FIND EVIL!** hackathon (SANS Institute,
Apr–Jun 2026). It extends Protocol SIFT — the SANS AI-orchestration POC
that pairs Claude Code with the SIFT Workstation — with an architectural
hallucination-prevention layer built on a typed evidence graph.

---

## Status

| Layer                       | Status | Tests          |
|-----------------------------|--------|----------------|
| Typed evidence graph        | Done   | 187 passing    |
| Content-addressed evidence store | Done | 24 passing  |
| Ingestion (Defender + Volatility) | Done | 35 passing |
| EVTX binary adapter         | Done   | 15 passing     |
| Orchestrator                | Done   | 11 passing     |
| Finding report + gate       | Done   | 13 passing     |
| MCP server (5 tools)        | Done   | 42 passing     |
| Agent-loop integration test | Done   | 2 passing      |
| Volatility binary execution | Week 2 | —              |
| Hunter agent + Claude Code config | Week 2 | —        |
| Accuracy harness + ground-truth cases | Week 3 | —    |
| Bypass test suite (5 attacks) | Week 3 | —            |
| Demo video                  | Week 3 | —              |

**Total: 327 tests passing, 18 integration tests opt-in (real malware data, ~7 min).**

---

## The five-minute demo

[ DEMO VIDEO LINK — added before submission ]

What the demo shows, against a real 16 MB Windows Defender event log (15,911 records, 10 detection events, 2 actual Trojan signatures):

1. **Ingestion.** GLAIVE's MCP server receives `ingest_artifact("Defender.evtx", "defender_evtx")`. The file is SHA-256 hashed into a content-addressed store; 15,901 unsupported event types are filtered out; 10 supported detection events become typed `AntivirusDetection` nodes in the graph.

2. **Hunt.** Claude Code calls `query_graph(node_type="AntivirusDetection", filters=[{"field": "threat_name", "op": "contains", "value": "Trojan"}])`. The graph returns real findings — `Trojan:Win32/Cloxer` detected at `08:21:44`, quarantined at `08:21:49`.

3. **Audit.** Claude Code calls `get_node_provenance(canonical_key=...)`. The node traces back through the graph → evidence hash → source file. Every byte is recoverable.

4. **The gate.** Claude Code calls `commit_finding(claim, supporting_node_keys=[real_key], confidence_hint="confirmed")`. The gate checks the graph evidence and *downgrades* to "inferred" — there's no corroborating edge yet, so "confirmed" isn't earned. The finding is committed, transparently downgraded.

5. **The gate refuses bypass.** Claude Code attempts `commit_finding` with a fabricated `supporting_node_key` referencing a process that was never observed. The gate rejects with `decision: rejected_missing_node`. Not via prompting — by construction.

---

## Why this wins

| Protocol SIFT's stated rule | How GLAIVE enforces it |
|---|---|
| "No hallucinations" | Findings reference graph nodes; nodes are only created from validated tool output |
| "Deterministic execution" | Tool outputs flow through Pydantic-validated MCP handlers, not raw stdout |
| "Evidence integrity" | Content-addressed evidence store (SHA-256), read-only path enforcement |
| "Verification" | `commit_finding` refuses any claim whose evidence_hash is not resolvable |

Protocol SIFT writes these as prompt instructions. GLAIVE writes them as code.

---

## What's GLAIVE's novel contribution?

GLAIVE adds **four things** to Protocol SIFT (see [Status](#status) for what's shipped today):

1. **A typed evidence graph** (Pydantic + NetworkX). Every forensic observation
   becomes a typed node or edge with provenance. Reasoning happens over the
   graph, not over LLM-summarized text. *(Shipped.)*
2. **A graph-verification MCP layer.** A small server (5 tools, not 50) that
   sits between Claude Code and the graph. The only way findings can be
   committed is through `commit_finding`, which rejects any claim that
   doesn't trace to a graph path. *(Shipped.)*
3. **A `graph-verification` skill for Protocol SIFT.** A `SKILL.md` that
   tells Claude Code how to use the graph layer — drops in alongside the
   existing memory-analysis / plaso-timeline / etc. skills. *(Week 2.)*
4. **A bypass test suite.** Five adversarial tests against GLAIVE's own
   constraints (prompt injection via evidence content, tool output poisoning,
   filesystem escape, etc.) with the architectural reason each one fails.
   *(Week 3.)*

GLAIVE does *not* replace Protocol SIFT. The base CLAUDE.md, the 5 existing
skills, the case template, and the bash-driven SIFT tool invocations are all
unchanged. GLAIVE plugs in.

---

## Quick start

> **Tested on:** SANS SIFT (WSL2 Ubuntu 22.04), Python 3.11
> **Status:** Week 1 complete (ingestion + graph + MCP server). Agent-driver CLI and demo recording in Weeks 2-3.

```bash
git clone https://github.com/aliyaalias19/glaive.git
cd glaive
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Verify the build (~2 seconds)

```bash
pytest
# Expected: 327 passed, 18 deselected
```

The 18 deselected tests are **integration tests** that run against a real binary EVTX file. To execute them, drop a real Windows Defender event log at `test_evidence/Defender.evtx` (instructions in [docs/EVIDENCE.md](docs/EVIDENCE.md)), then:

```bash
pytest -m integration
# Expected: 18 passed in ~7 minutes (binary EVTX parsing is heavy)
```

### Run the full agent-loop simulation

The single test that proves the architectural promise end-to-end:

```bash
pytest tests/mcp_server/test_agent_loop.py -m integration -v
```

This test simulates Claude Code calling all 5 MCP tools in sequence against real malware data, including a deliberate bypass attempt that the gate must reject. If this passes, every layer of GLAIVE — schema, graph, ingestion, MCP boundary, gate — works.

### Use the MCP server with Claude Code

Wire the server into Claude Code by adding to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "glaive": {
      "command": "python",
      "args": ["-m", "glaive.mcp_server"]
    }
  }
}
```

(Direct Claude-Code integration is finalized in Week 2.)

## Repository layout

### Present today

| Path                       | What's in it                                                              |
|----------------------------|---------------------------------------------------------------------------|
| `glaive/graph/`            | Pydantic schema: 10 node types, 12 edge types, NetworkX wrapper           |
| `glaive/evidence/`         | Content-addressed evidence store (SHA-256 + manifest)                     |
| `glaive/ingestion/`        | Parsers (Defender EVTX, Volatility) + EVTX binary adapter + orchestrator  |
| `glaive/reporting/`        | `FindingReport` — the gate (confidence-downgrade enforcement)             |
| `glaive/mcp_server/`       | MCP server (5 tools: ingest, query, provenance, commit, list)             |
| `tests/`                   | 327 tests; 18 marked `integration` (run against real binary EVTX)         |
| `docs/EVIDENCE_GRAPH_SCHEMA.md` | The full schema spec — 10 nodes, 12 edges, 5 principles               |
| `docs/DECISIONS.md`        | 29 strategic and design decisions with rationale                          |
| `ARCHITECTURE.md`          | System design and Trust Model                                             |
| `LIMITATIONS.md`           | What GLAIVE does **not** do                                               |
| `evidence_samples/`        | Manifest pointing at public evidence datasets                             |
| `verification/`            | Skeleton for the accuracy harness + bypass test suite (Week 2-3)          |

### Coming in Weeks 2-3

| Path                  | Status                                                                   |
|-----------------------|--------------------------------------------------------------------------|
| `ACCURACY_REPORT.md`  | Filled by `verification/harness.py` against ground-truth cases (Week 3)  |
| `BYPASS_TESTS.md`     | Five adversarial tests against the gate, each with architectural reason  |
| `glaive/cli.py`       | The `glaive investigate` command-line driver                             |
| Volatility integration | vol.py shell-out for memory dump ingestion (requires SRL evidence pack) |
| Demo video            | 5-minute screencast against real evidence                                |

---

## Hackathon compliance

Built for the **FIND EVIL!** hackathon (SANS Institute, Apr–Jun 2026).
This project is substantially new work created during the hackathon period.
Pre-existing dependencies (Protocol SIFT, Volatility 3, Plaso, python-evtx,
NetworkX, Pydantic) are unmodified open-source libraries. The graph schema,
MCP verification layer, graph-verification skill, and bypass test suite are
original contributions.

## License

MIT — see [LICENSE](LICENSE).
