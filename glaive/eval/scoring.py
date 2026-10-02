"""Score an investigation against an answer key.

Metrics
  recall           share of answer-key items covered by at least one finding
  precision_proxy  share of findings that cover at least one answer-key item
                   (a finding outside the key is not necessarily wrong - the
                   key lists what MUST be found - so this is a lower bound)
  attack_coverage  answer-key ATT&CK techniques also tagged on findings
  blocked          claims the gate rejected (hallucinations stopped)
  ungrounded_in_report  committed findings with an entity missing from their
                   evidence. By construction of the gate this should be 0;
                   the scorer re-checks it independently.

A finding "covers" an item when ALL the item's terms appear in the finding's
claim or in the attributes of the nodes it cites.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from glaive.reporting.grounding import check_grounding, evidence_haystack


@dataclass
class ItemResult:
    id: str
    title: str
    found: bool
    by: list[str] = field(default_factory=list)  # finding short ids


@dataclass
class EvalResult:
    items: list[ItemResult]
    findings: int
    findings_matching: int
    blocked: int
    ungrounded_in_report: int
    attack_expected: list[str]
    attack_found: list[str]

    @property
    def recall(self) -> float:
        return sum(i.found for i in self.items) / len(self.items) if self.items else 0.0

    @property
    def precision_proxy(self) -> float:
        return self.findings_matching / self.findings if self.findings else 0.0

    @property
    def attack_coverage(self) -> float:
        exp = set(self.attack_expected)
        return len(exp & set(self.attack_found)) / len(exp) if exp else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "recall": round(self.recall, 3), "precision_proxy": round(self.precision_proxy, 3),
            "attack_coverage": round(self.attack_coverage, 3), "findings": self.findings,
            "blocked_by_gate": self.blocked, "ungrounded_in_report": self.ungrounded_in_report,
            "items": [i.__dict__ for i in self.items],
        }

    def to_markdown(self) -> str:
        lines = ["| Item | Found | By finding |", "|---|---|---|"]
        for i in self.items:
            lines.append(f"| {i.id} {i.title} | {'yes' if i.found else 'NO'} | "
                         f"{', '.join(i.by[:4])} |")
        lines += ["", f"- Recall: **{self.recall:.0%}** ({sum(i.found for i in self.items)}"
                      f"/{len(self.items)})",
                  f"- Findings covering a key item: {self.findings_matching}/{self.findings}",
                  f"- ATT&CK technique coverage: {self.attack_coverage:.0%}",
                  f"- Claims blocked by the gate: {self.blocked}",
                  f"- Ungrounded statements in the final report: {self.ungrounded_in_report}"]
        return "\n".join(lines) + "\n"


def load_answer_key(path: Path) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def score_session(session: Any, answer_key: list[dict[str, Any]] | list[Any]) -> EvalResult:
    key = [k if isinstance(k, dict) else k.__dict__ for k in answer_key]
    findings = [f for f in session.report.findings if f.status != "rejected_by_analyst"]
    texts: dict[str, str] = {}
    ungrounded = 0
    for f in findings:
        keys = [tuple(k) for k in f.supporting_node_keys]
        hay = evidence_haystack(session.graph, keys, hops=0)
        texts[f.short_id] = (f.claim + "\n" + hay).lower()
        if not check_grounding(f.claim, session.graph, keys).ok:
            ungrounded += 1
    items, matched = [], set()
    for k in key:
        by = [fid for fid, text in texts.items()
              if all(term.lower() in text for term in k["terms"])]
        matched.update(by)
        items.append(ItemResult(k["id"], k["title"], bool(by), by))
    blocked = sum(1 for e in session.audit_log
                  if e.get("action") in ("gate_decision", "rule_finding")
                  and str(e.get("detail", {}).get("decision", "")).startswith("rejected"))
    expected = sorted({t for k in key for t in k.get("mitre", [])})
    found = sorted({t for f in findings for t in f.mitre_techniques})
    return EvalResult(items, len(findings), len(matched), blocked, ungrounded, expected, found)
