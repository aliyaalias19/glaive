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

## 4. Trust Model — How GLAIVE Layers on Protocol SIFT's Permissions

GLAIVE does **not** replace Protocol SIFT's permission model. It adds a
*commit-time* gate that Protocol SIFT lacks.

### What Protocol SIFT enforces today

Protocol SIFT's `~/.claude/settings.json` declares a permission model with
three parts:

**Allow list (excerpts):**
```
"Bash(*)"                  # any bash command at all
"Read"                     # any file read
"Write(./analysis/*)"      # writes restricted to working dirs
"Write(./reports/*)"
"Write(./exports/*)"
... 70 specific Bash(<tool> *) entries (vol, log2timeline, MFTECmd, rip.pl, ...)
```

**Deny list:**
```
"Read(./secrets/**)"
"Read(./**/*.key)" / "Read(./**/*.pem)"
"Bash(rm -rf:*)"           # blocks rm -rf, not plain rm
"Bash(dd:*)" / "Bash(wget:*)" / "Bash(curl:*)" / "Bash(ssh:*)"
"WebFetch"
```

**Stop hook:**
```
Appends "$(date -u): $CONVERSATION_SUMMARY" to ./analysis/forensic_audit.log
```

### Architectural gaps GLAIVE addresses

| Gap in Protocol SIFT | GLAIVE's response |
|---|---|
| `Bash(*)` allows arbitrary commands; the 70 specific entries are *intent*, not *enforcement* | The trust surface for **findings** narrows to 5 typed MCP tools. Bash remains for tool execution; only the graph gate produces report content. |
| Deny list is pattern-based and bypassable (e.g., `rm -rf` blocked, plain `rm` allowed) | Findings cannot enter the report through any bash path. `commit_finding` is the only producer. |
| No commit-time validation: a hallucinated finding written to `./reports/` is indistinguishable from a real one | Every committed finding must trace to graph paths with resolvable `evidence_hash`. If not, commit is rejected. |
| `forensic_audit.log` records that the agent ran, but not what it concluded or why | GLAIVE extends the same log with per-finding provenance: timestamp, finding ID, graph path used, evidence hashes referenced. |
| Path-based denies (`./secrets/**`) can be defeated by canonicalization tricks (`./secrets/../secrets/file`) | GLAIVE's MCP tools resolve paths with `Path.resolve()` before any access. Tested in Bypass Test #5. |

### Where the gate sits

```
Claude Code (Protocol SIFT)        GLAIVE (architectural enforcement)
─────────────────────────────────  ──────────────────────────────────
Bash(*) → forensic CLI tool

       ↓ stdout

[no validation]

       ↓ MCP call
                                   ingest_artifact()  ← validated against
                                                         Pydantic schema
                                   query_graph()      ← typed queries only

       ↓ findings drafted

                                   verify_claim()      ← must resolve to graph path
                                   commit_finding()    ← THE GATE

                                          ↓                ↓
                                   ./reports/findings.md   ./analysis/forensic_audit.log
                                                            (extended with provenance)
```

### Implication for bypass tests

The five bypass tests in `verification/bypass_tests/` are designed to attack
the gaps above:

1. **Prompt injection via evidence content** — content of an EVTX record asks the agent to commit a hallucinated finding. Defense: gate rejects unsupported claims regardless of agent state.
2. **Tool output poisoning** — malformed Volatility output that "looks like" a process listing. Defense: Pydantic validation rejects before ingestion.
3. **Resource exhaustion** — 100k synthetic processes in memory dump. Defense: bounded graph queries with pagination.
4. **Confused deputy** — agent prompted to "skip verification for this one." Defense: commit_finding is a separate code path; prompt cannot bypass.
5. **Filesystem escape via evidence path** — path like `../../../etc/passwd`. Defense: `Path.resolve()` canonicalization rejects out-of-case paths.
