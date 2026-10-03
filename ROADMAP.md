# Roadmap

Where GLAIVE is going and why. Each version has one theme and a "done when"
test that can be checked, not a feature wish-list.

| Version | Theme | Done when... |
|---|---|---|
| v0.2 Core (released) | Make it a real product | You can drop in a Windows triage folder and get a verified report in the browser, with or without an AI model |
| v0.3 AI depth | Make the AI trustworthy, and prove it | Accuracy is published on public data it was not built on, AI is compared with rules alone, "Ask the case" answers with citations, log poisoning is blocked, and personal data never leaves the machine unmasked |
| v0.4 Scale and integrations | Fit into real teams | GB-scale cases; memory, registry, KAPE and Linux evidence; SIEM, threat intel and chat-ops (Feishu, Slack); M365 and cloud audit logs; Azure OpenAI and Bedrock; a shared team server with Docker Compose |
| v0.5 Frontier | Things nobody else has | GLAIVE-mini trained with the gate as its reward, forensics of hijacked AI agents, multimodal evidence, training / CTF mode |
| v1.0 Stable | Ready for outside users | Stable case file and plugin API, docs, signed releases, an independent security review, a public leaderboard |

## v0.3 AI depth

Measurement comes first, so every later change can show whether it helped.

- **Benchmark on public data.** EVTX-ATTACK-SAMPLES (labelled by ATT&CK
  tactic), OTRF Security-Datasets (labelled by technique) and a benign
  baseline (NextronSystems evtx-baseline) for false positives.
- **Rules alone vs rules plus AI**, per model provider, with cost and time.
- **Confidence calibration**: how often findings at each confidence level match
  the answer key.
- **Privacy**: case data is pseudonymised before it is sent to a cloud model,
  and a local-only mode refuses cloud models entirely.
- **Audit trail**: every model and tool call is traced (OpenTelemetry
  conventions, local file by default).
- **Evidence search (GraphRAG)**: hybrid keyword and vector search over the
  evidence graph, with recall@k measured.
- **Past-case memory**: findings from earlier cases, searchable on request.
- **Ask the case**: answers cite the evidence; uncited or ungrounded sentences
  are removed.
- **Log poisoning**: a measured attack set, not only unit tests.

## v0.4 Scale and integrations

DuckDB for large cases, parallel per-host investigation, Volatility in the
pipeline, registry hives, KAPE / EZ-tools output, Linux logs, M365 / Entra
and CloudTrail, SIEM and threat-intel connectors, Feishu and Slack,
Azure OpenAI and Bedrock, provider prompt caching, Docker Compose.

## v0.5 Frontier

- **GLAIVE-mini**: a small open model trained with reinforcement learning
  where the verification gate is the reward (grounded claims, real citations,
  no inflated confidence). It ships only if it beats its base model on
  held-out public data.
- **AI-agent forensics**: investigate hijacked AI agents from MCP tool logs
  and agent transcripts.
- **Multimodal evidence**: screenshots, phishing emails and documents.
- **Training mode**: guided cases and CTF-style challenges.

## Deliberately not planned

These come up often. They do not make GLAIVE better at its job:

- Fine-tuning on synthetic data (results would not be honest; see GLAIVE-mini
  for the version that would be).
- Agent frameworks such as LangGraph or CrewAI: the hand-written agents are
  easier to audit, which matters in forensics.
- Message queues (Kafka, Celery) and Kubernetes: GLAIVE is local-first.
- A semantic response cache: every case is different, and a shared cache could
  leak data between cases.
- Server vector databases: the search index lives in the case folder.
