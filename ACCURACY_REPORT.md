# Accuracy Report

Measured on GLAIVE 0.2.0. Reproduce with:

```bash
glaive demo --offline        # rules only, no AI model
pytest -m integration        # real samples; set GLAIVE_EVTX_SAMPLES first
```

## Demo case "Operation Invoice" (synthetic, with answer key)

Two hosts, 247 events, twelve attack steps hidden in normal activity. Rules
only, no AI model:

| Item | Found |
|---|---|
| GT1 Malicious document: Word spawned PowerShell | yes |
| GT2 Encoded PowerShell download from the C2 server | yes |
| GT3 Microsoft Defender real-time protection disabled | yes |
| GT4 Persistence through a Run key pointing at svchost32.exe | yes |
| GT5 Payload beacons to the C2 server over port 443 | **no** |
| GT6 Account and group discovery | **no** |
| GT7 LSASS memory dumped with comsvcs.dll | yes |
| GT8 Brute force then successful logon to FILESRV-01 | yes |
| GT9 Malicious service installed on FILESRV-01 | yes |
| GT10 Shadow copies deleted (ransomware preparation) | yes |
| GT11 Security log cleared on FILESRV-01 | yes |
| GT12 Prompt injection planted for AI investigators | yes |

- Recall: **10/12 (83%)**
- Findings that match an answer-key item: 13/14 (the 14th is a true but
  unlisted detail)
- ATT&CK technique coverage: 86%
- Ungrounded statements in the report: **0**

Why the two misses: the beacon (GT5) and the discovery commands (GT6) only
trigger medium/low alerts or none, and rule triage reports medium and above.
These are exactly what the Hunter agent is for; with a model connected the
test suite shows the combined result reaching 12/12 using a scripted model.
How well a real model does depends on the model.

## Public attack samples (real data)

All 278 EVTX files of [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(37,364 events): every file ingests without errors, every graph node traces to
a stored evidence file (no fabricated provenance), and rule triage commits
findings with zero ungrounded statements. There is no answer key for this set,
so recall is not measured on it.

## Not yet measured

- Real-model recall and precision on the demo case, per provider.
- False-positive rate on benign baselines.
- Confidence calibration (how often "confirmed" findings are correct).
