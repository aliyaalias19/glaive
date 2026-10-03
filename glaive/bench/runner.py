"""Run GLAIVE over a benchmark dataset and score it against the labels.

    results = run_benchmark(cases, mode="rules")
    print(results.to_markdown())

Each case is investigated in its own throw-away session, exactly as a user
would run it. Two levels are scored:

  alerts    what the detection rules flagged (any level)
  findings  what the investigation committed through the gate
            (rules mode: RuleInvestigator; ai mode: the full agent team)

For attack cases, a level "hits" the tactic when one of its ATT&CK tactics
equals the dataset's label, and the technique when a technique matches at
parent level (T1003.001 ~ T1003). For benign cases every alert or finding is
a false alarm.
"""
from __future__ import annotations

import shutil
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from glaive import __version__
from glaive.bench.datasets import BenchCase
from glaive.detection.attack import same_tactic, same_technique, tactic_name, tactics_of
from glaive.detection.sigma import SigmaRule, load_rules

LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass
class CaseResult:
    id: str
    title: str
    expected_tactics: list[str]
    expected_techniques: list[str]
    benign: bool
    events: int = 0
    alerts: int = 0
    alerts_by_level: dict[str, int] = field(default_factory=dict)
    alert_rules: list[str] = field(default_factory=list)
    alert_tactics: list[str] = field(default_factory=list)
    alert_techniques: list[str] = field(default_factory=list)
    findings: int = 0
    findings_by_confidence: dict[str, int] = field(default_factory=dict)
    finding_tactics: list[str] = field(default_factory=list)
    finding_techniques: list[str] = field(default_factory=list)
    blocked_by_gate: int = 0
    tokens: int = 0
    seconds: float = 0.0
    error: str | None = None

    # ---- hits -----------------------------------------------------------------

    def tactic_hit(self, level: str) -> bool:
        found = self.alert_tactics if level == "alerts" else self.finding_tactics
        return any(same_tactic(e, f) for e in self.expected_tactics for f in found)

    def technique_hit(self, level: str) -> bool:
        found = self.alert_techniques if level == "alerts" else self.finding_techniques
        return any(same_technique(f, e) for e in self.expected_techniques for f in found)

    def detected(self, level: str) -> bool:
        return (self.alerts if level == "alerts" else self.findings) > 0


@dataclass
class BenchResult:
    dataset: str
    mode: str
    model: str | None
    rules: str
    glaive_version: str
    started_at: str
    cases: list[CaseResult]
    seconds: float = 0.0

    # ---- aggregates --------------------------------------------------------------

    @property
    def attack_cases(self) -> list[CaseResult]:
        return [c for c in self.cases if not c.benign and c.error is None]

    @property
    def benign_cases(self) -> list[CaseResult]:
        return [c for c in self.cases if c.benign and c.error is None]

    def rate(self, level: str, what: str) -> tuple[int, int]:
        """(hits, total) for 'detected', 'tactic' or 'technique'."""
        pool = self.attack_cases
        if what == "technique":
            pool = [c for c in pool if c.expected_techniques]
        elif what == "tactic":
            pool = [c for c in pool if c.expected_tactics]
        fn = {"detected": CaseResult.detected, "tactic": CaseResult.tactic_hit,
              "technique": CaseResult.technique_hit}[what]
        return sum(fn(c, level) for c in pool), len(pool)

    def per_tactic(self, level: str) -> list[tuple[str, int, int]]:
        groups: dict[str, list[CaseResult]] = {}
        for c in self.attack_cases:
            for t in c.expected_tactics[:1]:
                groups.setdefault(t, []).append(c)
        return [(t, sum(c.tactic_hit(level) for c in cs), len(cs))
                for t, cs in sorted(groups.items(), key=lambda kv: tactic_name(kv[0]))]

    def false_alarms(self) -> dict[str, Any]:
        cases = self.benign_cases
        events = sum(c.events for c in cases)
        by_level: Counter[str] = Counter()
        rules: Counter[str] = Counter()
        for c in cases:
            by_level.update(c.alerts_by_level)
            rules.update(c.alert_rules)
        alerts = sum(c.alerts for c in cases)
        return {"machines": len(cases), "events": events, "alerts": alerts,
                "alerts_per_10k_events": round(alerts / events * 10_000, 2) if events else 0.0,
                "alerts_by_level": dict(by_level),
                "findings": sum(c.findings for c in cases),
                "medium_or_higher": sum(v for k, v in by_level.items()
                                        if LEVELS.index(k) >= 2),
                "top_rules": rules.most_common(10)}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "dataset": self.dataset, "mode": self.mode, "model": self.model,
            "rules": self.rules, "glaive_version": self.glaive_version,
            "started_at": self.started_at, "seconds": round(self.seconds, 1),
            "cases_total": len(self.cases),
            "cases_failed": sum(1 for c in self.cases if c.error),
            "tokens": sum(c.tokens for c in self.cases),
        }
        if self.attack_cases:
            out["summary"] = {level: {what: dict(zip(("hits", "total"),
                                                     self.rate(level, what), strict=True))
                                      for what in ("detected", "tactic", "technique")}
                              for level in ("alerts", "findings")}
            out["per_tactic"] = {level: [{"tactic": t, "name": tactic_name(t), "hits": h,
                                          "total": n} for t, h, n in self.per_tactic(level)]
                                 for level in ("alerts", "findings")}
        if self.benign_cases:
            out["false_alarms"] = self.false_alarms()
        out["cases"] = [asdict(c) for c in self.cases]
        return out

    def to_markdown(self) -> str:
        def pct(h: int, n: int) -> str:
            return f"{h / n:.0%} ({h}/{n})" if n else "n/a"

        lines = [f"## {self.dataset} - {self.mode}"
                 + (f" ({self.model})" if self.model else ""), "",
                 f"GLAIVE {self.glaive_version}, rules: {self.rules}, "
                 f"{len(self.cases)} cases in {self.seconds:.0f}s"
                 + (f", {sum(c.tokens for c in self.cases):,} tokens" if self.mode == "ai" else "")
                 + ".", ""]
        failed = [c for c in self.cases if c.error]
        if self.attack_cases:
            lines += ["| | Alerts | Findings |", "|---|---|---|"]
            for what, label in (("detected", "Something flagged"),
                                ("tactic", "Right ATT&CK tactic"),
                                ("technique", "Right technique (where labelled)")):
                lines.append(f"| {label} | {pct(*self.rate('alerts', what))} | "
                             f"{pct(*self.rate('findings', what))} |")
            lines += ["", "| Tactic (label) | Alerts | Findings |", "|---|---|---|"]
            fa = {t: (h, n) for t, h, n in self.per_tactic("findings")}
            for t, h, n in self.per_tactic("alerts"):
                lines.append(f"| {tactic_name(t)} ({t}) | {pct(h, n)} | {pct(*fa.get(t, (0, n)))} |")
        if self.benign_cases:
            fa2 = self.false_alarms()
            lines += ["", f"Benign baseline: {fa2['machines']} machine(s), {fa2['events']:,} events, "
                      f"**{fa2['alerts']} false alarms** ({fa2['alerts_per_10k_events']} per 10,000 "
                      f"events; {fa2['medium_or_higher']} at medium or higher), "
                      f"{fa2['findings']} findings committed.", ""]
            if fa2["top_rules"]:
                lines += ["| Rule | False alarms |", "|---|---|"]
                lines += [f"| {r} | {n} |" for r, n in fa2["top_rules"]]
        if failed:
            lines += ["", f"{len(failed)} case(s) failed: "
                      + "; ".join(f"{c.id}: {c.error}" for c in failed[:5])]
        return "\n".join(lines) + "\n"


# ---- running -----------------------------------------------------------------------

RouterFactory = Callable[[], Any]


def _finding_attack(session: Any, f: Any) -> tuple[list[str], list[str]]:
    techniques = list(f.mitre_techniques)
    tags_tactics: list[str] = []
    for key in f.supporting_node_keys:
        k = tuple(key)
        if k and k[0] == "Alert" and session.graph.has_node(k):
            a = session.graph.get_node(k)
            techniques += [t for t in a.mitre_techniques if t not in techniques]
            tags_tactics += [t for t in a.mitre_tactics if t not in tags_tactics]
    tactics = tactics_of(techniques)
    tactics += [t for t in tags_tactics if t not in tactics]
    return tactics, techniques


def run_case(case: BenchCase, rules: list[SigmaRule], mode: str = "rules",
             router_factory: RouterFactory | None = None, max_steps: int = 20,
             workdir: Path | None = None) -> CaseResult:
    from glaive.agents import Investigation, RuleInvestigator
    from glaive.ingestion.pipeline import ingest_path
    from glaive.mcp_server.session import GlaiveSession

    res = CaseResult(case.id, case.title, case.tactics, case.techniques, case.benign)
    tmp = Path(tempfile.mkdtemp(prefix="glaive-bench-", dir=workdir))
    start = time.perf_counter()
    try:
        session = GlaiveSession(analysis_dir=tmp / "case", case_name=case.id)
        for p in case.paths:
            res.events += ingest_path(session, p, rules=rules).events_total
        if res.events == 0:
            raise ValueError("no events could be read")
        alerts = list(session.graph.find_nodes("Alert"))
        res.alerts = len(alerts)
        res.alerts_by_level = dict(Counter(a.level for a in alerts))
        res.alert_rules = [a.title for a in alerts]
        res.alert_tactics = sorted({t for a in alerts for t in a.mitre_tactics})
        res.alert_techniques = sorted({t for a in alerts for t in a.mitre_techniques})
        if mode == "ai":
            router = router_factory() if router_factory else None
            if router is None:
                raise RuntimeError("ai mode needs a configured model (see 'glaive models')")
            Investigation(session, router, max_steps=max_steps).run()
            res.tokens = router.tokens_used
        else:
            RuleInvestigator(session).run()
        findings = list(session.report.findings)
        res.findings = len(findings)
        res.findings_by_confidence = dict(Counter(f.confidence for f in findings))
        tac: set[str] = set()
        tech: set[str] = set()
        for f in findings:
            a, b = _finding_attack(session, f)
            tac |= set(a)
            tech |= set(b)
        res.finding_tactics, res.finding_techniques = sorted(tac), sorted(tech)
        res.blocked_by_gate = sum(
            1 for e in session.audit_log if e.get("action") in ("gate_decision", "rule_finding")
            and str(e.get("detail", {}).get("decision", "")).startswith("rejected"))
    except Exception as e:  # one bad case must not stop the benchmark
        res.error = f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        res.seconds = round(time.perf_counter() - start, 2)
        shutil.rmtree(tmp, ignore_errors=True)
    return res


def run_benchmark(cases: list[BenchCase], *, dataset: str, mode: str = "rules",
                  sigma_paths: list[Path] | None = None, router_factory: RouterFactory | None = None,
                  max_steps: int = 20, progress: Callable[[int, int, CaseResult], None] | None = None,
                  workdir: Path | None = None) -> BenchResult:
    if mode not in ("rules", "ai"):
        raise ValueError("mode must be 'rules' or 'ai'")
    rules, report = load_rules(sigma_paths or [])
    model = None
    if mode == "ai":
        probe = router_factory() if router_factory else None
        if probe is None:
            raise RuntimeError("ai mode needs a configured model (see 'glaive models')")
        model = probe.describe()
    rules_label = "built-in" + "".join(f" + {Path(p).name}" for p in sigma_paths or [])
    result = BenchResult(dataset, mode, model, f"{rules_label} ({report.loaded} rules)",
                         __version__, datetime.now(UTC).isoformat(timespec="seconds"), [])
    start = time.perf_counter()
    for i, case in enumerate(cases, 1):
        r = run_case(case, rules, mode, router_factory, max_steps, workdir)
        result.cases.append(r)
        if progress:
            progress(i, len(cases), r)
    result.seconds = time.perf_counter() - start
    return result
