"""GLAIVE accuracy harness.

Runs GLAIVE against ground-truth cases and produces ACCURACY_REPORT.md.

For each case in verification/ground_truth/, the harness:
  1. Invokes glaive on the case's evidence directory.
  2. Parses the resulting findings.
  3. Compares them to the case's labeled ground-truth findings.
  4. Computes precision, recall, F1, hallucination count, false-positive count.
  5. Writes a per-case section to ACCURACY_REPORT.md.

Not yet implemented. Built out in Week 3.
"""
from __future__ import annotations


def main() -> None:
    raise NotImplementedError(
        "Accuracy harness is wired up in Week 3. "
        "Until then, manual evaluation against verification/ground_truth/ writeups."
    )


if __name__ == "__main__":
    main()
