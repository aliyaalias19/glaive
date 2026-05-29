
# Real-evidence integration tests

GLAIVE has 18 tests marked `@pytest.mark.integration`. They run against a real

binary Windows Defender event log, and are excluded from the default `pytest`

run for speed (binary EVTX parsing is heavy). To run them you need a real

`Defender.evtx` file at `test_evidence/Defender.evtx`.

## Getting a real Defender.evtx

The file lives on every Windows machine at:

C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx



You'll need administrator privileges to copy it. From an elevated PowerShell:

```powershell

Copy-Item "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx" `

          "<path-to-glaive>\test_evidence\Defender.evtx"

```

(If you're using WSL like we do for development, the destination is

`\\wsl.localhost\<Distro>\home\<user>\glaive\test_evidence\Defender.evtx`.)

## Privacy note

The Defender log records every malware detection on the host machine, including

file paths and process names. **The `test_evidence/` directory is gitignored.**

If you fork this repo, double-check that you don't accidentally commit your

local evidence.

## Running the integration tests

Once the file is in place:

```bash

pytest -m integration             # all 18 integration tests, ~7 min

pytest tests/mcp_server/test_agent_loop.py -m integration -v

                                  # just the full agent-loop simulation

```

## What if I don't have a Windows machine?

You can run the unit tests (327 of them) which provide full coverage of every

layer using synthetic test fixtures. The integration tests are *additional*

proof that the pipeline handles real binary data; they aren't required for

build verification.

