# Limitations

> Honesty over perfection. These are the things GLAIVE deliberately does **not**
> do, or does imperfectly. Documenting them is part of the design.

## What GLAIVE does not do

- **Replace Protocol SIFT.** GLAIVE is an extension layer. The base
  Protocol SIFT CLAUDE.md, skills, and case template are unmodified.
- **Live system response.** GLAIVE analyzes captured evidence, not running hosts.
- **Malware reverse engineering.** GLAIVE detects suspicious binaries via
  artifact correlation but does not perform deep static or dynamic analysis.
- **Cloud forensics.** Current evidence types: memory dumps, Windows event logs,
  registry hives, filesystem images. AWS / Azure / GCP audit logs are out of
  scope for this submission.
- **Network packet inspection.** Network artifacts are sourced from host-side
  logs and memory; we do not parse PCAP.
- **Human-in-the-loop approval workflows.** Protocol SIFT explicitly forbids
  asking the user mid-task. GLAIVE uses the graph as critic, not a human.

## Known weaknesses

(Filled in during accuracy harness runs in Week 3.)

## Things that look like bugs but are not

(Filled in as we discover them.)
