"""Run a complete investigation: triage -> hunt -> challenge -> report.

    result = Investigation(session, router).run()

Stages (each logged to the session audit log, which the web UI streams):
  1. triage   RuleInvestigator turns high/critical alerts into findings
              (always runs; no model needed)
  2. hunt     HunterAgent explores the graph and commits findings (model)
  3. review   SkepticAgent tries to refute each finding (model)
  4. report   ReporterAgent writes a cited summary (model, or deterministic)
  5. save     the case file is written
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from glaive.agents.agents import (
    AgentRun,
    HunterAgent,
    ReportDraft,
    ReporterAgent,
    RuleInvestigator,
    SkepticAgent,
)
from glaive.agents.prompts import PROMPT_VERSION
from glaive.llm.router import Router


@dataclass
class InvestigationResult:
    mode: str
    seconds: float
    triage_findings: int
    hunter: AgentRun | None
    skeptic: dict[str, int] | None
    report: ReportDraft
    llm: dict[str, Any] | None
    findings_total: int
    findings_pending: int
    extra: dict[str, Any] = field(default_factory=dict)


class Investigation:
    def __init__(self, session: Any, router: Router | None = None, *, max_steps: int = 30,
                 skeptic: bool = True, language: str = "en", min_alert_level: str = "medium",
                 task: str | None = None) -> None:
        self.session = session
        self.router = router
        self.max_steps = max_steps
        self.use_skeptic = skeptic
        self.language = language
        self.min_alert_level = min_alert_level
        self.task = task

    def _emit(self, kind: str, info: dict[str, Any]) -> None:
        actor = info.get("agent", "investigation")
        self.session.log(actor, kind, **info)

    def run(self) -> InvestigationResult:
        start = time.perf_counter()
        mode = "ai" if self.router else "offline"
        if self.router is not None and self.router.on_event is None:
            self.router.on_event = lambda k, i: self._emit(k, {"agent": "router", **i})
        self._emit("investigation_started", {"mode": mode, "prompt_version": PROMPT_VERSION,
                                             "models": self.router.describe() if self.router
                                             else None})

        triage = RuleInvestigator(self.session, self.min_alert_level, self._emit).run()
        hunter_run = skeptic_counts = None
        if self.router is not None:
            hunter_run = HunterAgent(self.router, self.session, self.max_steps,
                                     self._emit).run(self.task)
            if self.use_skeptic:
                skeptic_counts = SkepticAgent(self.router, self.session, emit=self._emit).run()
        report = ReporterAgent(self.router, self.session, self.language, self._emit).run()

        result = InvestigationResult(
            mode=mode, seconds=time.perf_counter() - start,
            triage_findings=sum(1 for r in triage if r.get("committed")),
            hunter=hunter_run, skeptic=skeptic_counts, report=report,
            llm=self.router.summary() if self.router else None,
            findings_total=len(self.session.report.findings),
            findings_pending=len(self.session.report.pending()))
        self.session.summary_markdown = report.markdown
        self._emit("investigation_finished", {
            "mode": mode, "seconds": round(result.seconds, 1),
            "findings": result.findings_total, "pending_approval": result.findings_pending,
            "report_generated_by": report.generated_by,
            "tokens_used": self.router.tokens_used if self.router else 0})
        self.session.save()
        return result
