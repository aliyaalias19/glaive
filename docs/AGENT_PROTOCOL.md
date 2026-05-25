# Agent Protocol

> **Status:** Skeleton — Day 1. Written in detail in Week 2.

How Claude Code (the agent) and the GLAIVE MCP server communicate.

There is **no second LLM** (no separate Critic agent). The critic is the
graph itself — `commit_finding` rejects unsupported claims architecturally.

## Investigation loop

1. Agent receives case task (case directory with evidence)
2. Agent reads `~/.claude/skills/graph-verification/SKILL.md` (our new skill)
3. Agent runs SIFT tools via bash (as Protocol SIFT does today)
4. Agent calls `ingest_artifact` to load tool outputs into the graph
5. Agent calls `query_graph` to investigate
6. Agent drafts findings
7. Agent calls `commit_finding` — accepted or rejected
8. If rejected: agent revises, retries (with backoff)
9. If unresolvable: agent calls `flag_unresolvable`
10. Final report generated from committed findings

## Loop invariants

- A finding in the report exists *if and only if* it passed `commit_finding`.
- A graph node exists *if and only if* it was produced by `ingest_artifact`
  from a validated tool output.
- Every committed finding traces to an `evidence_hash` resolvable in the
  content-addressed evidence store.
