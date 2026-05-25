# GLAIVE Architecture

> **Status:** Skeleton — Day 1. Filled in during Day 2.

## 1. Design thesis

Protocol SIFT lets Claude Code reason over text. Text-based reasoning is
where hallucinations live. **GLAIVE forces reasoning over a typed evidence
graph, where every claim must correspond to a structural path** — making
hallucination architecturally impossible, not merely discouraged.

## 2. System overview

```
            Protocol SIFT (unchanged baseline)
           ┌────────────────────────────────┐
           │  Claude Code                   │
           │  + ~/.claude/CLAUDE.md         │
           │  + skills/ (memory, plaso, …)  │
           └──────────────┬─────────────────┘
                          │  bash (existing)
                          ▼
              ┌─────────────────────┐
              │ SIFT forensic tools │  vol, log2timeline, evtxexport, rip.pl, ...
              └──────────┬──────────┘
                         │  stdout
─────────────────────────┼───────────  GLAIVE layer ─────────
                         ▼
              ┌─────────────────────┐
              │ Ingestion parsers   │  Pydantic-validated → typed nodes/edges
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │ Typed evidence graph│  NetworkX, schema-enforced
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │ GLAIVE MCP server   │  5 tools: query / verify / commit / explain / unresolved
              └──────────┬──────────┘
                         │
              ┌──────────┴───────────┐
              ▼                      ▼
        New skill:               graph-as-critic
        graph-verification       (rejects findings
        SKILL.md                  that don't trace)
                         │
                         ▼
              ┌─────────────────────┐
              │   Report (MD + JSON, full provenance)   │
              └─────────────────────┘
```

## 3. Layers (Day 2 expansion)

- **Ingestion** — wraps SIFT tools, normalizes output, populates graph
- **Graph** — typed nodes (Process, File, RegistryKey, etc.) and edges
- **MCP server** — the verification surface Claude Code talks to
- **Skill** — `~/.claude/skills/graph-verification/SKILL.md`
- **Verification harness** — accuracy + bypass tests

## 4. Trust boundaries

The MCP server is the trust boundary. Claude Code can read from the graph
through investigation tools, but can only emit findings through
`commit_finding`, which validates them against the graph at commit time.
This is the architectural part of "no hallucinations" — not a prompt
instruction, an actual gate.
