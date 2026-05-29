# Skill: Graph-Verified Findings (GLAIVE)

> **Installation:** GLAIVE installed from source (`pip install -e .` in the
> GLAIVE repo). The MCP server is registered in `~/.claude/mcp.json` and
> exposes 5 tools under the namespace `glaive`. See the GLAIVE repo's
> `README.md` for the full setup.
>
> This skill teaches Claude Code to use those tools so that every finding
> produced during a forensic investigation is **grounded in a typed evidence
> graph** rather than produced from LLM summaries of raw artifacts.

## Overview

Use this skill **for every forensic investigation that needs to produce
auditable findings**. Plaso, Volatility, Sleuthkit, and other SIFT tools
extract raw observations from evidence; GLAIVE turns those observations into
typed graph nodes and only allows findings that trace back through the graph
to specific source bytes.

The core promise: **a finding committed through this skill cannot be a
hallucination** — the gate rejects any claim whose supporting nodes don't
exist in the graph, and downgrades confidence claims that the graph evidence
doesn't support. This is enforced architecturally (in `commit_finding`), not
by prompting.

---

## Tools

All tools are MCP tools under the `glaive` server. Invoke them like any
other MCP tool — Claude Code's standard tool-call protocol applies.

| Tool | Purpose |
|------|---------|
| `glaive.ingest_artifact` | Parse a forensic artifact (Defender EVTX, Volatility output, etc.) into typed graph nodes |
| `glaive.query_graph` | Find graph nodes by type + declarative filters (`eq`, `contains`, `gt`, `lt`, `exists`) |
| `glaive.get_node_provenance` | Trace a node back to its source evidence (hash, file, ingest time) |
| `glaive.commit_finding` | **THE GATE.** Record a finding; the only way to enter the report |
| `glaive.list_evidence` | List all evidence files ingested into the current session |

---

## When to use this skill

Reach for this skill when:

- You are producing **any finding** that will go into a report a human will trust.
- You are about to claim that a specific entity (a process, a registry key, a file) is suspicious or malicious — you must back the claim with graph nodes.
- You need to provide **provenance** for a finding (the byte-level trace).
- You see contradictory signals from different tools and need to surface the disagreement honestly.

Do **not** use this skill when:

- The user explicitly asks for a free-form prose analysis without a structured finding (rare; usually a misread).
- You are exploring or hypothesizing — exploration happens with `query_graph`, but findings are only committed when you can back them.

---

## Workflow

### Step 1 — Acquire evidence into the graph

For each piece of evidence you need to reason about, call `ingest_artifact`:

```text
glaive.ingest_artifact(path="/cases/srl/exports/Defender.evtx",
                       source_type="defender_evtx")
```

`source_type` is required and explicit (no auto-detection by extension).
Supported types are listed in the tool's error message if you supply an
unknown one — currently `defender_evtx`; more sources land in Week 2.

The tool returns:

- `evidence_hash` — the SHA-256 of the source file
- `nodes_added` — typed graph nodes created
- `nodes_merged` — nodes that already existed and were enriched
- `skipped_event_count` — records the parser filtered out
- `graph_totals` — current node/edge counts

If the call returns `status: "error"`, do **not** retry blindly. Read the
`error` field. `file_not_found` means the path is wrong; `unsupported_source_type`
means you used a string that doesn't match a known parser.

### Step 2 — Hunt for relevant findings

Query the graph with declarative filters:

```text
glaive.query_graph(
    node_type="AntivirusDetection",
    filters=[
        {"field": "threat_name", "op": "contains", "value": "Trojan"}
    ],
    limit=100
)
```

Supported ops: `eq`, `contains`, `gt`, `lt`, `exists`. Filters are
AND-combined. Missing fields never match (defensive).

The result has:

- `total_matched` — how many nodes matched (regardless of `limit`)
- `returned` — how many summaries are in the response
- `truncated` — true if `total_matched > returned`
- `nodes` — list of node summaries, each with `canonical_key` (the lookup tuple) and `evidence_hash`

**The `canonical_key` is what you pass to `get_node_provenance` and
`commit_finding`.** Treat it as opaque — don't construct it yourself,
always obtain it from a query.

### Step 3 — Trace provenance before claiming

Before committing a finding about a node, trace it to source bytes:

```text
glaive.get_node_provenance(canonical_key=<key from step 2>)
```

This returns:

- `evidence_hash` — the SHA-256 of the source file
- `derivation` — the tool/path that produced the node (e.g. `"Defender EVTX"`)
- `observed_at` — when the node entered the graph
- `observed_by` — for multi-source nodes (e.g. a Process seen by both psscan + pslist), the list of tools that observed it
- `source_evidence` — the original filename, size, ingest time

If `observed_by` is short (one tool) or absent, the node has weaker
corroboration — note this in your finding's `confidence_hint`.

### Step 4 — Commit through the gate

```text
glaive.commit_finding(
    claim="Windows Defender detected Trojan:Win32/Cloxer in a downloaded ZIP",
    supporting_node_keys=[<canonical_key from step 2>],
    confidence_hint="suspected"
)
```

**Confidence levels:**

- `confirmed` — multiple independent evidence sources corroborate
- `suspected` — one source, plausible interpretation
- `inferred` — derived from cross-correlation, no direct observation
- `disputed` — sources disagree on a non-identity field

The gate evaluates your claim and returns one of four decisions:

- `accepted` — finding committed at your requested confidence
- `downgraded_confidence` — finding committed at a *lower* confidence because graph evidence doesn't support your hint
- `rejected_missing_node` — at least one `supporting_node_key` doesn't exist in the graph
- `rejected_empty_support` — you didn't provide any supporting keys

### Step 5 — Handle gate decisions (self-correction)

This is the most important step. The gate's response IS the agent's feedback loop.

**On `accepted` or `downgraded_confidence`:** the finding is committed.
A downgrade is not a failure — the finding is real, just less certain than
you claimed. Note the downgrade in your investigation narrative.

**On `rejected_missing_node`:** you referenced a key that doesn't exist.
Common causes: (a) you constructed the key yourself instead of obtaining
it from `query_graph`; (b) the key is from a previous session; (c) the
evidence hasn't been ingested yet. Re-query the graph and use the real key.

**On `rejected_empty_support`:** you tried to commit a finding with no
supporting evidence. Find supporting nodes via `query_graph` first.
**Never** try to commit a finding without graph backing.

---

## Gate decision handling — full reference

The gate is the architectural enforcement. Internalize these rules:

1. **You cannot fabricate supporting keys.** The gate looks up each key
   in the graph; missing keys = rejection. Always obtain keys from
   `query_graph`.

2. **You cannot inflate confidence.** The gate compares your `confidence_hint`
   against graph-derived confidence (which considers `confirmed_by` on
   edges, `observed_by` on multi-source nodes, and `disagreements` for
   disputed fields). The gate's confidence is the ceiling.

3. **The gate's confidence is final.** If the gate downgrades to `inferred`,
   the finding lands at `inferred` in the report. You cannot re-commit
   the same finding hoping for a different verdict — the graph evidence
   determines the outcome, not your re-phrasing.

4. **Round-trip the `canonical_key` carefully.** Keys returned from
   `query_graph` have datetime elements serialized as ISO 8601 strings
   (JSON has no native datetime). The gate's `_coerce_key` restores them
   when you pass the key back. Do not modify the key elements.

---

## Anti-patterns

These are mistakes that will produce wrong outputs, gate rejections, or
both:

| Anti-pattern | Why it fails |
|--------------|--------------|
| Writing a finding as free prose, skipping `commit_finding` | The report only contains what's been committed. Prose disappears from the structured output. |
| Constructing a `canonical_key` from scratch | The gate looks up the exact tuple. Made-up keys are missing keys. |
| Calling `commit_finding` with `supporting_node_keys=[]` | Empty support = rejection. Always back claims with graph nodes. |
| Setting `confidence_hint="confirmed"` for every finding | The gate will downgrade based on actual evidence. Better to set the hint honestly. |
| Re-running `ingest_artifact` on the same file every turn | Evidence is content-addressed; ingestion is idempotent. Once it's in the graph, leave it. |
| Using the graph as a search engine for prose | The graph is typed structured data. Use `query_graph` with filters; don't treat it as full-text. |
| Asking the user for clarification mid-investigation | Protocol SIFT explicitly forbids this. The gate is the critic — use it instead of asking the user. |

---

## Example session

A realistic investigation against a Windows Defender event log:

```text
# Step 1: list what's loaded (start of session)
> glaive.list_evidence()
< {"status": "ok", "evidence_count": 0, ...}

# Step 2: ingest the Defender log
> glaive.ingest_artifact(path="/cases/srl/exports/Defender.evtx",
                         source_type="defender_evtx")
< {"status": "ok", "nodes_added": 10, "skipped_event_count": 15901,
   "evidence_hash": "0e43313e...", ...}

# Step 3: hunt for Trojan detections
> glaive.query_graph(node_type="AntivirusDetection",
                     filters=[{"field": "threat_name", "op": "contains",
                               "value": "Trojan"}])
< {"status": "ok", "total_matched": 2, "nodes": [
    {"canonical_key": ["AntivirusDetection", "rd01", 1116,
                       "2025-04-12T08:21:44.894831+00:00",
                       "Trojan:Win32/Cloxer"],
     "threat_name": "Trojan:Win32/Cloxer",
     "detection_time": "2025-04-12T08:21:44.894831+00:00",
     "evidence_hash": "0e43313e...", ...},
    ...
  ]}

# Step 4: trace provenance on the first hit
> glaive.get_node_provenance(canonical_key=<key from step 3>)
< {"status": "ok",
   "evidence_hash": "0e43313e...",
   "derivation": "Defender EVTX",
   "source_evidence": {"original_name": "Defender.evtx", ...}}

# Step 5: commit the finding
> glaive.commit_finding(
    claim="Windows Defender detected Trojan:Win32/Cloxer in user's downloads",
    supporting_node_keys=[<canonical_key>],
    confidence_hint="suspected"
  )
< {"status": "ok", "decision": "downgraded_confidence",
   "final_confidence": "inferred",
   "reason": "Agent claimed 'suspected' but graph evidence supports only 'inferred'.",
   "committed": true,
   "finding_id": "76f6b1b3-..."}

# Step 6: handle the downgrade — note it in the narrative
# The finding is committed at 'inferred' because the AntivirusDetection node
# has no corroborating edges yet. This is correct behavior: a single detection
# event is direct evidence the detection happened, but the broader claim about
# its significance is an inference.
```

---

## Integration with other Protocol SIFT skills

This skill **composes with**, not replaces, the existing SIFT skills:

- **memory-analysis** produces Volatility output → `ingest_artifact` with a future `volatility_processes` source_type populates `Process` nodes
- **windows-artifacts** produces registry and event log artifacts → `ingest_artifact` with `defender_evtx` (and future EVTX sources) populates the graph
- **plaso-timeline** produces a super-timeline → future GLAIVE adapters will turn timeline events into typed nodes
- **sleuthkit** produces filesystem evidence → future adapters will populate `File` and MFT-derived edges
- **yara-hunting** produces signature hits → future adapters will populate `YaraMatch` nodes (v2 schema)

Use the SIFT skills to **extract** evidence; use this skill to **commit findings** about that evidence.

---

## Limitations (v1)

- Only `defender_evtx` source is supported today. More land in Week 2 (Volatility processes, EVTX Security, MFT, registry).
- `confidence` heuristics treat standalone nodes (no corroborating edges) as `inferred`. This is conservative — a single detection event committed with `confidence_hint="suspected"` will be downgraded. Honest, but watch for it.
- Path safety in `ingest_artifact` is basic (existence + file-type checks). Full directory sandboxing arrives in Week 2.
- See `docs/EVIDENCE_GRAPH_SCHEMA.md` for the complete node/edge type list and identity rules.
