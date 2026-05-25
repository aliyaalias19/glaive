# MCP Tool Reference

> **Status:** Skeleton — Day 1. Finalized when implemented in Week 2.

GLAIVE exposes a **small** MCP surface — five tools, not fifty. The discipline
of a small toolset is intentional: every additional tool is another bypass
surface and another way the agent can wander.

Protocol SIFT's existing bash-driven tool execution (Volatility, Plaso, etc.)
is **unchanged**. GLAIVE sits beside it: tool outputs are funneled into the
typed graph by our ingestion layer, and the agent queries the graph via these
MCP tools to produce findings.

## The five tools

### 1. `ingest_artifact(path, artifact_type)`
Read a forensic tool's output (Volatility JSON, EVTX export, RegRipper output,
etc.), validate against the schema for that artifact type, and populate the
typed graph. Returns the count of nodes/edges added and the content hashes of
ingested artifacts.

### 2. `query_graph(criteria)`
Investigation primitive. Find nodes/edges matching typed criteria, traverse
neighborhoods, find paths between nodes, get a time-windowed timeline. The
*only* way the agent reasons over evidence.

### 3. `verify_claim(claim)`
Given a structured claim (subject, predicate, object, time_window), confirm
whether the graph contains the supporting path. Returns the path if found,
or a structured rejection with the missing edges if not.

### 4. `commit_finding(finding)`
The **gate**. A finding may only be committed if its claims pass `verify_claim`.
This is the architectural enforcement of "no hallucinations": findings that
don't trace to graph paths are rejected at commit time, not by convention.

### 5. `flag_unresolvable(question, attempted_paths)`
Lets the agent admit defeat gracefully. Logs the unresolved question and the
graph paths it tried. Counts toward the audit trail, not against accuracy.

## Why not more tools?

Protocol SIFT lets Claude Code call any bash command, which is a wide attack
surface. GLAIVE intentionally narrows the *reasoning* surface (graph queries)
without taking away the *execution* surface (bash). The agent still uses
SIFT tools through bash; it just can't make claims without going through the
graph.
