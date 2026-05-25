# Case Candidates — Day 1 Shortlist

> Working document. Final selection committed on Day 7 after hand-solve.
> NOTE: After D4 (see DECISIONS.md), we commit to ONE case, not three.

## Selection criteria

A good case for GLAIVE is:
- **Multi-source.** Both memory and EVTX at minimum. Bonus: registry hives,
  MFT, Prefetch. Single-source cases don't exercise the graph.
- **Has a documented solution.** Either an official writeup or a high-quality
  community writeup. We need ground truth to measure accuracy against.
- **Realistic intrusion narrative.** Not a CTF puzzle. We want something that
  resembles real IR work: initial access → privilege esc → persistence → action.
- **Public.** Either downloadable without paywalls or freely available with
  attribution. SANS provides starter case data via the Devpost resources page.

## Primary source: SANS starter case data

The Devpost Resources page links to https://sansorg.egnyte.com/fl/HhH7crTYT4JK —
sample disk images and memory captures provided by SANS. **Default to this
unless we find something dramatically better.**

## Candidates (browse and fill in)

| # | Name | Source | Evidence types | Why a candidate | Ground truth | Notes |
|---|------|--------|----------------|-----------------|--------------|-------|
| 1 | SANS starter case | Devpost Resources | TBD until downloaded | What the judges expect to see | TBD | DEFAULT |
| 2 | CyberCorp Case 1 | CyberDefenders #c56 | memory, MFT, registry, traffic, EVTX, Prefetch | Full kit, every node type exercised | forensicskween writeup | strong backup |
| 3 |  |  |  |  |  |  |

## Notes from browsing

(Free-form notes as you browse — what surprised you, what looks too easy,
what looks too hard.)
