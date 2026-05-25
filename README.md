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

## The five-minute demo

[ DEMO VIDEO LINK — added before submission ]

What you'll see:
1. Raw evidence (memory image + Windows event logs) ingested into a typed graph.
2. Claude Code (configured via Protocol SIFT) reasons over the graph, never raw text.
3. The graph rejects an unsupported claim — the agent retries with new evidence.
4. Every committed finding traces to a specific byte offset in the source artifact.

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

GLAIVE adds **four things** to Protocol SIFT:

1. **A typed evidence graph** (Pydantic + NetworkX). Every forensic observation
   becomes a typed node or edge with provenance. Reasoning happens over the
   graph, not over LLM-summarized text.
2. **A graph-verification MCP layer.** A small server (5 tools, not 50) that
   sits between Claude Code and the graph. The only way findings can be
   committed is through `commit_finding`, which rejects any claim that
   doesn't trace to a graph path.
3. **A `graph-verification` skill for Protocol SIFT.** A new `SKILL.md` that
   tells Claude Code how to use the graph layer. Drops in alongside the
   existing memory-analysis / plaso-timeline / etc. skills.
4. **A bypass test suite.** Five adversarial tests against GLAIVE's own
   constraints (prompt injection via evidence content, tool output poisoning,
   filesystem escape, etc.) with the architectural reason each one fails.

GLAIVE does *not* replace Protocol SIFT. The base CLAUDE.md, the 5 existing
skills, the case template, and the bash-driven SIFT tool invocations are all
unchanged. GLAIVE plugs in.

---

## Quick start

> **Tested on:** SANS SIFT (WSL2 Ubuntu 22.04), Python 3.11

```bash
# Prereq: Protocol SIFT installed (see https://www.sans.org/tools/sift-workstation/)
git clone git@github.com:aliyaalias19/glaive.git
cd glaive
./install.sh
export ANTHROPIC_API_KEY="sk-ant-..."

# Set up the case directory (matches Protocol SIFT convention)
export CASE=/cases/srl
mkdir -p ${CASE}/{analysis,exports,reports}
# Download evidence into ${CASE}/ (see evidence_samples/README.md)

# Run GLAIVE inside the case directory
cd ${CASE}
glaive investigate .
```

Outputs land in `${CASE}/analysis/`, `${CASE}/exports/`, and `${CASE}/reports/`
— matching Protocol SIFT's documented output convention.

Open `reports/findings.md` for the narrative; `reports/findings.json` for the
machine-readable findings with full provenance.

## Repository layout

| Path                  | What's in it                                              |
|-----------------------|-----------------------------------------------------------|
| `glaive/`             | Source: ingestion, graph, MCP server, agents, reporting   |
| `docs/`               | Architecture, schema, MCP tool reference, decisions       |
| `verification/`       | Ground-truth cases, accuracy harness, bypass tests        |
| `evidence_samples/`   | Manifest pointing at public evidence datasets             |
| `tests/`              | Unit tests                                                |
| `ARCHITECTURE.md`     | System design and design rationale                        |
| `ACCURACY_REPORT.md`  | Auto-generated precision/recall against ground truth      |
| `BYPASS_TESTS.md`     | Adversarial tests against GLAIVE's own constraints        |
| `LIMITATIONS.md`      | What GLAIVE does **not** do (honesty over perfection)     |
| `docs/DECISIONS.md`   | Strategic decisions and their reasoning                   |

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
