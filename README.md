# GLAIVE

**An AI forensic investigator that can only say what the evidence proves.**

Point GLAIVE at Windows logs. It builds a typed evidence graph, runs
detection rules, and lets AI agents investigate, but every finding must pass
a verification gate before anyone sees it:

- it must cite real graph nodes built from your evidence files;
- every IP, path, hash, domain, account or threat name it mentions must
  appear in that evidence;
- its confidence is computed from how many independent sources corroborate
  it, not from what the model claims;
- a second agent (the Skeptic) tries to refute it, and high-severity
  findings wait for a human to approve them.

Each sentence in the report links back to the exact log record and the
SHA-256 of the original file.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Try it in one minute

```bash
git clone https://github.com/aliyaalias19/glaive.git
cd glaive
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"          # on Linux, ".[dev,fast]" adds a ~1000x faster EVTX reader

glaive demo --serve
```

`glaive demo` generates "Operation Invoice", a realistic two-host intrusion
(phishing document, encoded PowerShell, Defender disabled, Run-key
persistence, C2 beacon, LSASS dump, brute force, malicious service, shadow
copy deletion, log clearing, and a prompt injection planted for AI
investigators). It investigates the case, scores the result against the
answer key, writes `report.html`, and opens the web app.

No API key is needed. Without a model GLAIVE runs in **rules-only mode** and
still finds 10 of the 12 attack steps. Add a model to let the agents find the
rest.

## Investigate your own evidence

```bash
glaive investigate C:\triage\host01.zip          # a file, folder or .zip
glaive investigate ./kape-output --language zh   # 中文 report
glaive serve cases/host01                        # review findings in the browser
```

Accepted today: Windows **EVTX** files (Security, System, Sysmon, PowerShell,
Microsoft Defender) and **JSON / JSON-Lines** exports (EvtxECmd, Chainsaw,
`evtx_dump`, or GLAIVE's own format). Files are recognised by content, not by
name. Everything else is still hashed into the evidence store for chain of
custody.

## Use any AI model, or none

Set one or more keys. GLAIVE uses them in order and falls back automatically
when one fails (retries, circuit breaker, token budget).

| Region | Providers |
|---|---|
| International | Claude (`ANTHROPIC_API_KEY`), GPT (`OPENAI_API_KEY`), Gemini (`GEMINI_API_KEY`), OpenRouter |
| China | DeepSeek, Qwen (DashScope), Kimi (Moonshot), GLM (Zhipu), Doubao (Volcengine Ark), SiliconFlow |
| Offline / self-hosted | Ollama (`OLLAMA_MODEL=qwen3:8b`), or any OpenAI-compatible server: vLLM, SGLang, LMDeploy, llama.cpp (`GLAIVE_BASE_URL`) |

```bash
glaive models        # what is configured, and how to add more
```

See [.env.example](.env.example) for every setting. Default model names were
checked against provider documentation in October 2026; override any of them
with `GLAIVE_MODEL` or `<PROVIDER>_MODEL`.

## Use it from Claude Code, Cursor, Dify or Cherry Studio (MCP)

```json
{ "mcpServers": { "glaive": { "command": "glaive", "args": ["mcp", "--case", "cases/host01"] } } }
```

Tools: `ingest_artifact`, `case_overview`, `list_alerts`, `query_graph`,
`get_neighbors`, `get_timeline`, `get_node_provenance`, `commit_finding`
(the gate), `list_evidence`, `save_case`.

## Run it in Docker

```bash
docker build -t glaive .
docker run -p 8765:8765 -v "$PWD/cases:/cases" -e GLAIVE_WEB_TOKEN=choose-a-secret glaive
# open http://127.0.0.1:8765/?token=choose-a-secret
```

The container runs as an unprivileged user and, because it listens on all
interfaces, always requires the access token.

## Security model

- Evidence is copied into a content-addressed store, made read-only and
  hashed (SHA-256) before it is parsed; `glaive verify` re-checks every file.
- Everything read from evidence is treated as data. Text aimed at AI
  investigators ("ignore previous instructions...") is detected in English
  and Chinese, raised as an alert, and passed to models only inside randomly
  tagged delimiters.
- Archives are checked for path traversal, zip bombs and symlinks before
  extraction.
- The web app listens on 127.0.0.1 by default. Without a token it rejects
  requests addressed to any other host name (DNS rebinding) and
  state-changing requests from other websites (cross-site request forgery).
  On any other address it requires `GLAIVE_WEB_TOKEN`. The page loads nothing
  from third parties, so it works on isolated analysis machines.
- 21 adversarial tests in `verification/bypass_tests` try to get false
  findings past the gate; see [BYPASS_TESTS.md](BYPASS_TESTS.md).

## How it works

```
evidence (.evtx / .json / .zip)
   |  hashed into a read-only, content-addressed store (SHA-256)
   v
parsers  ->  typed evidence graph  (processes, users, hosts, files, registry,
   |         network endpoints, services, tasks, script blocks, alerts)
   v
detections: 27 built-in Sigma rules (+ any SigmaHQ folder) and correlations
   |        (brute force -> logon, defender disabled -> attack, prompt injection)
   v
agents:  Rules triage (no AI) -> Hunter -> Skeptic -> Reporter
   |        every claim goes through commit_finding (the gate)
   v
case.glaive (SQLite) + report.html + web app + MCP
```

| Part | What it does |
|---|---|
| `glaive/graph/` | Pydantic node/edge types, merge rules, multi-source confidence |
| `glaive/evidence/` | Content-addressed store; hash-while-copy; read-only; `verify()` |
| `glaive/ingestion/` | EVTX (Rust fast path + python-evtx fallback), JSON/JSONL, Windows parser, folder/zip pipeline with zip-slip and zip-bomb protection |
| `glaive/detection/` | Dependency-free Sigma engine (loads ~90% of SigmaHQ's Windows rules) and correlation rules |
| `glaive/reporting/` | The gate: node existence, claim grounding, confidence derivation, analyst review; HTML report |
| `glaive/llm/` | Provider adapters (OpenAI-compatible + Anthropic), router, environment config |
| `glaive/agents/` | Toolbox, Hunter (plan + ReAct), Skeptic, Reporter (cited sentences only), runner |
| `glaive/security/` | Prompt-injection detection (English and Chinese) and spotlighting of untrusted data |
| `glaive/case/` | The portable `.glaive` case file |
| `glaive/web/` | FastAPI app with a live event stream; single-page UI that works offline |
| `glaive/eval/` | Scores an investigation against an answer key |

## Measured, not claimed

| Check | Result |
|---|---|
| Test suite | 503 tests + 21 adversarial bypass tests, on Windows and Linux, Python 3.11 and 3.12, mcp 1.x and 2.x |
| Real data | All 278 files of the public [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) set (37,364 events) ingest with no errors and no fabricated provenance (`pytest -m integration` with `GLAIVE_EVTX_SAMPLES` set) |
| Speed | That set ingests, detects and links in about 3 seconds with the fast EVTX reader |
| Demo case, rules only | Recall 10/12 attack steps, 13/14 findings match the answer key, 0 ungrounded statements ([ACCURACY_REPORT.md](ACCURACY_REPORT.md)) |
| Sigma compatibility | 2,168 of 2,410 SigmaHQ Windows rules load; the rest use log sources or Sigma features GLAIVE does not support yet and are reported, never mis-evaluated |

## Honest limits

- Windows logs only so far. Memory images (Volatility), disk images,
  registry hives, Linux, macOS and cloud audit logs are on the roadmap.
- The gate checks concrete entities (IPs, paths, hashes, names). A claim can
  still overstate what the evidence means using ordinary words. The Skeptic
  agent and human approval exist for that.
- Process identity across logs uses (host, PID, start time to the second).
  Very fast PID reuse within one second can merge two processes.
- No attribution ("this was APT-X") and no legal conclusions.
- The AI agents were tested with scripted models and HTTP-level mocks; their
  real-world quality depends on the model you connect.

Design notes and history: [ARCHITECTURE.md](ARCHITECTURE.md),
[docs/DECISIONS.md](docs/DECISIONS.md), [BYPASS_TESTS.md](BYPASS_TESTS.md),
[LIMITATIONS.md](LIMITATIONS.md), [CHANGELOG.md](CHANGELOG.md).

GLAIVE began as a submission to the SANS **FIND EVIL!** hackathon (2026) as a
verification layer for Protocol SIFT; it still works that way through MCP.

## License

MIT, see [LICENSE](LICENSE).
