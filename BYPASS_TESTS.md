# Bypass Tests

> Adversarial tests run against GLAIVE's own security constraints. Each test
> documents an attack, the expected architectural defense, and the actual result.

See `verification/bypass_tests/` for the test code itself.

## Test catalogue

| # | Attack vector                          | Defense layer                  | Status   |
|---|----------------------------------------|--------------------------------|----------|
| 1 | Prompt injection via evidence content  | Typed graph isolation          | Planned  |
| 2 | Tool output poisoning                  | Pydantic schema validation     | Planned  |
| 3 | Resource exhaustion                    | Bounded graph queries          | Planned  |
| 4 | Confused deputy (skip-graph prompt)    | Architectural commit gate      | Planned  |
| 5 | Filesystem escape via evidence path    | Path canonicalization in MCP   | Planned  |

Detailed write-up per test follows the same template:
- **Attack vector** — exact attack payload / scenario
- **Hypothesized defense** — why this *should* fail
- **Test code** — pointer to the `verification/bypass_tests/` file
- **Actual result** — pass / fail, with reasoning
- **If failed:** what we'd change architecturally
