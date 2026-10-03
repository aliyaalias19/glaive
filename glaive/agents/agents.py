"""GLAIVE's investigation team.

    RuleInvestigator  no model needed: turns high-severity alerts into
                      gate-verified findings (works offline, always runs first)
    HunterAgent       LLM, ReAct-style tool loop with an upfront plan
                      (plan-and-solve); learns from gate rejections
    SkepticAgent      LLM, adversarial review: tries to refute each finding;
                      can only lower confidence, never raise it
    ReporterAgent     LLM, executive summary in which every sentence must
                      cite a finding; uncited sentences are deleted

All agents act only through AgentToolbox, so every fact they record passes
the same verification gate as a human analyst's would.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from glaive.agents import prompts
from glaive.agents.toolbox import LEVEL_RANK, AgentToolbox, NodeArgs
from glaive.llm.router import Router
from glaive.llm.types import BudgetExceeded, LLMError, Message
from glaive.mcp_server import tools as core
from glaive.observability import span
from glaive.reporting.grounding import check_grounding
from glaive.reporting.report import CONFIDENCE_RANK, SEVERITY_RANK, Finding, SkepticReview
from glaive.security.injection import spotlight

Emit = Callable[[str, dict[str, Any]], None]

_LEVEL_TO_SEVERITY = {"informational": "info", "low": "low", "medium": "medium",
                      "high": "high", "critical": "critical"}


def _noop(kind: str, info: dict[str, Any]) -> None:
    pass


# =============================================================================
# Offline: rules -> findings
# =============================================================================


class RuleInvestigator:
    """Deterministic triage. For each (rule, host) with alerts at or above
    `min_level`, commit one finding citing up to five of its alerts."""

    def __init__(self, session: Any, min_level: str = "medium", emit: Emit = _noop) -> None:
        self.session = session
        self.min_level = min_level
        self.emit = emit

    def run(self) -> list[dict[str, Any]]:
        with span("invoke_agent rules", **{"gen_ai.operation.name": "invoke_agent",
                                           "gen_ai.agent.name": "rules"}) as sp:
            results = self._run()
            sp.set("glaive.findings.committed", sum(1 for r in results if r.get("committed")))
            return results

    def _run(self) -> list[dict[str, Any]]:
        floor = LEVEL_RANK[self.min_level]
        groups: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for a in self.session.graph.find_nodes("Alert"):
            if LEVEL_RANK.get(a.level, 0) >= floor:
                groups[(a.rule_id, a.host_hostname)].append(a)
        for av in self.session.graph.find_nodes("AntivirusDetection"):
            # Skip Defender events a Sigma alert already covers (no duplicate findings).
            if any(True for _ in self.session.graph.incoming_edges(av.canonical_key(), "Triggered")):
                continue
            groups[(f"defender:{av.event_id}:{av.threat_name}", av.host_hostname)].append(av)

        already = {(f.author, tuple(map(tuple, f.supporting_node_keys[:1])))
                   for f in self.session.report.findings}
        results = []
        ordered = sorted(groups.items(), key=lambda kv: (
            -max(LEVEL_RANK.get(getattr(n, "level", "high"), 3) for n in kv[1]),
            min(n.detection_time for n in kv[1])))
        for (rule_id, host), nodes in ordered:
            nodes.sort(key=lambda n: n.detection_time)
            cited = nodes[:5]
            first = cited[0]
            author = f"rule:{rule_id}"
            if (author, (first.canonical_key(),)) in already:
                continue
            claim, severity, mitre = self._describe(first, len(nodes), host)
            keys = [n.canonical_key() for n in cited]
            # Also cite the process the first alert is about: its creation record
            # is an independent observation the gate can weigh.
            for e in self.session.graph.outgoing_edges(first.canonical_key(), "Triggered"):
                if e.role == "process":
                    keys.append(e.target_key)
                    break
            res = core.do_commit_finding(
                self.session, claim, [list(core._json_safe(k)) for k in keys],
                "suspected", severity=severity, mitre_techniques=mitre,
                rationale=f"{len(nodes)} matching event(s); first at "
                          f"{first.detection_time.isoformat()}.", author=author)
            self.emit("rule_finding", {"agent": "rules", "rule": rule_id, "host": host,
                                       "decision": res.get("decision"), "claim": claim,
                                       "reason": res.get("reason")})
            results.append(res)
        return results

    @staticmethod
    def _describe(node: Any, count: int, host: str) -> tuple[str, str, list[str]]:
        if node.node_type == "AntivirusDetection":
            what = node.threat_name or node.event_description or f"event {node.event_id}"
            where = f" in {node.file_path}" if node.file_path else ""
            claim = f"Microsoft Defender on {host} reported {what}{where}"
            if node.action_taken:
                claim += f" (action: {node.action_taken})"
            sev = "high" if node.threat_name or node.event_id in (5001, 5010, 5012) else "medium"
            mitre = ["T1562.001"] if node.threat_name is None else []
            return claim + ".", sev, mitre
        detail = ""
        for f in ("CommandLine", "ScriptBlockText", "ImagePath", "TargetObject", "TaskName",
                  "Image", "TargetUserName", "IpAddress"):
            v = node.matched_fields.get(f)
            if v:
                v = " ".join(v.split())
                detail = f" ({f}: {v[:180]}{'...' if len(v) > 180 else ''})"
                break
        times = f" {count} times" if count > 1 else ""
        claim = f"Detection rule '{node.title}' fired on {host}{times}{detail}."
        return claim, _LEVEL_TO_SEVERITY.get(node.level, "medium"), list(node.mitre_techniques)


# =============================================================================
# LLM agents
# =============================================================================


@dataclass
class AgentRun:
    steps: int = 0
    tool_calls: int = 0
    commits_accepted: int = 0
    commits_rejected: int = 0
    finished: bool = False
    summary: str | None = None
    stopped_reason: str = ""
    transcript: list[dict[str, Any]] = field(default_factory=list)


def _tool_loop(router: Router, toolbox: AgentToolbox, messages: list[Message], max_steps: int,
               emit: Emit, agent: str, run: AgentRun) -> None:
    specs = toolbox.specs()
    for _ in range(max_steps):
        run.steps += 1
        try:
            resp = router.complete(messages, specs, max_tokens=2048)
        except BudgetExceeded as e:
            run.stopped_reason = f"budget: {e}"
            return
        except LLMError as e:
            run.stopped_reason = f"model error: {e}"
            emit("agent_error", {"agent": agent, "error": str(e)[:300]})
            return
        msg = resp.message
        messages.append(msg)
        if msg.content:
            emit("agent_thought", {"agent": agent, "text": msg.content[:2000]})
            run.transcript.append({"role": "assistant", "text": msg.content[:2000]})
        if not msg.tool_calls:
            run.stopped_reason = "model stopped calling tools"
            return
        for call in msg.tool_calls:
            run.tool_calls += 1
            emit("tool_call", {"agent": agent, "tool": call.name,
                               "args": json.dumps(call.arguments, default=str)[:600]})
            result = toolbox.execute(call)
            messages.append(Message.tool_result(call, result))
            if call.name == "commit_finding" and toolbox.commits:
                last = toolbox.commits[-1]
                if last.get("committed"):
                    run.commits_accepted += 1
                else:
                    run.commits_rejected += 1
                emit("gate_decision", {"agent": agent, "decision": last.get("decision"),
                                       "reason": str(last.get("reason"))[:300],
                                       "claim": call.arguments.get("claim", "")[:300]})
            run.transcript.append({"tool": call.name, "args": call.arguments,
                                   "result_chars": len(result)})
        if toolbox.finished:
            run.finished = True
            run.summary = toolbox.finished
            run.stopped_reason = "finished"
            return
    run.stopped_reason = "step limit reached"


class HunterAgent:
    def __init__(self, router: Router, session: Any, max_steps: int = 30, emit: Emit = _noop):
        self.router = router
        self.session = session
        self.max_steps = max_steps
        self.emit = emit

    def run(self, task: str | None = None) -> AgentRun:
        with span("invoke_agent hunter", **{"gen_ai.operation.name": "invoke_agent",
                                            "gen_ai.agent.name": "hunter",
                                            "glaive.prompt_version": prompts.PROMPT_VERSION}) as sp:
            run = self._run(task)
            sp.set("glaive.steps", run.steps)
            sp.set("glaive.findings.accepted", run.commits_accepted)
            sp.set("glaive.findings.rejected", run.commits_rejected)
            sp.set("glaive.stopped_reason", run.stopped_reason)
            return run

    def _run(self, task: str | None) -> AgentRun:
        toolbox = AgentToolbox(self.session, author="hunter")
        run = AgentRun()
        task = task or ("Investigate this case. Determine what the attacker did, in order, and "
                        "commit verified findings for each significant step.")
        messages = [Message.system(prompts.HUNTER_SYSTEM), Message.user(task)]
        self.emit("agent_started", {"agent": "hunter", "prompt_version": prompts.PROMPT_VERSION,
                                    "model": self.router.describe()})
        _tool_loop(self.router, toolbox, messages, self.max_steps, self.emit, "hunter", run)
        self.emit("agent_finished", {"agent": "hunter", "steps": run.steps,
                                     "accepted": run.commits_accepted,
                                     "rejected": run.commits_rejected,
                                     "reason": run.stopped_reason})
        return run


_JSON_OBJ = re.compile(r"\{.*\}", re.S)


class SkepticAgent:
    def __init__(self, router: Router, session: Any, max_steps_per_finding: int = 6,
                 max_findings: int = 15, emit: Emit = _noop):
        self.router = router
        self.session = session
        self.max_steps = max_steps_per_finding
        self.max_findings = max_findings
        self.emit = emit

    def _evidence_brief(self, f: Finding) -> str:
        toolbox = AgentToolbox(self.session, readonly=True)
        parts = [toolbox._node(NodeArgs(canonical_key=list(core._json_safe(tuple(key)))))
                 for key in f.supporting_node_keys[:5]]
        return json.dumps(parts, default=str)[:8000]

    def review(self, f: Finding) -> SkepticReview | None:
        with span("invoke_agent skeptic", **{"gen_ai.operation.name": "invoke_agent",
                                             "gen_ai.agent.name": "skeptic",
                                             "glaive.finding.id": f.finding_id}) as sp:
            review = self._review(f)
            sp.set("glaive.skeptic.verdict", review.verdict if review else "unparsed")
            return review

    def _review(self, f: Finding) -> SkepticReview | None:
        toolbox = AgentToolbox(self.session, author="skeptic", readonly=True)
        brief = spotlight(self._evidence_brief(f), "tool_result")
        messages = [Message.system(prompts.SKEPTIC_SYSTEM), Message.user(
            f"FINDING {f.short_id} (confidence {f.confidence}, severity {f.severity}):\n"
            f"{f.claim}\n\nRationale given: {f.rationale or 'none'}\n\n"
            f"Cited evidence:\n{brief}")]
        run = AgentRun()
        _tool_loop(self.router, toolbox, messages, self.max_steps, self.emit, "skeptic", run)
        final = next((m.content for m in reversed(messages)
                      if m.role == "assistant" and m.content), None)
        for attempt in range(2):
            review = self._parse(final)
            if review:
                return review
            if attempt == 0:
                messages.append(Message.user(
                    "Reply now with ONLY the JSON object described in your instructions."))
                try:
                    resp = self.router.complete(messages, None, max_tokens=600)
                except LLMError:
                    return None
                messages.append(resp.message)
                final = resp.message.content
        return None

    @staticmethod
    def _parse(text: str | None) -> SkepticReview | None:
        if not text:
            return None
        m = _JSON_OBJ.search(text)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
            data = {k: data.get(k) for k in ("verdict", "argument", "alternative_explanation")}
            return SkepticReview.model_validate(data)
        except (json.JSONDecodeError, ValidationError, AttributeError):
            return None

    def run(self) -> dict[str, int]:
        todo = sorted([f for f in self.session.report.findings if f.skeptic is None],
                      key=lambda f: (-SEVERITY_RANK[f.severity], -CONFIDENCE_RANK[f.confidence]))
        counts = {"upheld": 0, "weakened": 0, "refuted": 0, "unparsed": 0}
        for f in todo[:self.max_findings]:
            self.emit("skeptic_reviewing", {"finding_id": f.finding_id, "claim": f.claim[:200]})
            review = self.review(f)
            if review is None:
                counts["unparsed"] += 1
                continue
            self.session.report.apply_skeptic(f.finding_id, review)
            counts[review.verdict] += 1
        return counts


# =============================================================================
# Reporter
# =============================================================================

_CITE = re.compile(r"\[F(\d+)\]")
_SENTENCE = re.compile(r"(?<=[.!?。！？])\s+|\n+")


@dataclass
class ReportDraft:
    markdown: str
    sentences_kept: int
    sentences_removed: list[str]
    citation_map: dict[str, str]  # "F1" -> finding_id
    generated_by: str


def numbered_findings(session: Any) -> list[tuple[str, Finding]]:
    finals = [f for f in session.report.sorted_findings() if f.status != "rejected_by_analyst"]
    return [(f"F{i}", f) for i, f in enumerate(finals, 1)]


def verify_cited_text(text: str, cites: dict[str, Finding], graph: Any) -> tuple[str, int, list[str]]:
    """Keep only sentences that cite real findings and whose entities are
    grounded in those findings' evidence. Headings and blank lines pass."""
    kept_lines: list[str] = []
    removed: list[str] = []
    kept = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept_lines.append(line)
            continue
        prefix = re.match(r"^\s*([-*]|\d+\.)\s+", line)
        lead = prefix.group(0) if prefix else ""
        body = line[len(lead):]
        good = []
        for sent in _SENTENCE.split(body):
            s = sent.strip()
            if not s:
                continue
            ids = [f"F{n}" for n in _CITE.findall(s)]
            if not ids or any(i not in cites for i in ids):
                removed.append(s)
                continue
            keys = [tuple(k) for i in ids for k in cites[i].supporting_node_keys]
            if not check_grounding(_CITE.sub("", s), graph, keys).ok:
                removed.append(s)
                continue
            good.append(s)
            kept += 1
        if good:
            kept_lines.append(lead + " ".join(good))
    return "\n".join(kept_lines).strip() + "\n", kept, removed


def deterministic_summary(session: Any, language: str = "en") -> str:
    """A plain summary built only from the findings (used without a model)."""
    rows = numbered_findings(session)
    zh = language == "zh"
    if not rows:
        return ("## 摘要\n\n未发现经过验证的结论。\n" if zh
                else "## Summary\n\nNo verified findings were committed.\n")
    crit = [r for r in rows if r[1].severity in ("critical", "high")]
    lines = ["## 摘要" if zh else "## Summary", ""]
    if zh:
        lines.append(f"本次调查共确认 {len(rows)} 项经证据验证的发现，其中 {len(crit)} 项为高危或严重。")
    else:
        lines.append(f"The investigation produced {len(rows)} evidence-verified findings, "
                     f"{len(crit)} of them high or critical severity.")
    lines += ["", "## 主要发现" if zh else "## Key findings", ""]
    for fid, f in rows[:25]:
        lines.append(f"- **{f.severity.upper()}** ({f.confidence}) {f.claim} [{fid}]")
    return "\n".join(lines) + "\n"


class ReporterAgent:
    def __init__(self, router: Router | None, session: Any, language: str = "en",
                 emit: Emit = _noop):
        self.router = router
        self.session = session
        self.language = language
        self.emit = emit

    def run(self) -> ReportDraft:
        with span("invoke_agent reporter", **{"gen_ai.operation.name": "invoke_agent",
                                              "gen_ai.agent.name": "reporter"}) as sp:
            draft = self._run()
            sp.set("glaive.report.generated_by", draft.generated_by)
            sp.set("glaive.report.sentences_kept", draft.sentences_kept)
            sp.set("glaive.report.sentences_removed", len(draft.sentences_removed))
            return draft

    def _run(self) -> ReportDraft:
        rows = numbered_findings(self.session)
        cites = {fid: f for fid, f in rows}
        cmap = {fid: f.finding_id for fid, f in rows}
        if self.router is None or not rows:
            md = deterministic_summary(self.session, self.language)
            return ReportDraft(md, len(rows), [], cmap, "deterministic")
        facts = "\n".join(
            f"[{fid}] severity={f.severity} confidence={f.confidence} status={f.status}"
            f"{' skeptic=' + f.skeptic.verdict if f.skeptic else ''} time={f.committed_at.date()}:"
            f" {f.claim}" for fid, f in rows[:60])
        system = prompts.REPORTER_SYSTEM.format(
            language=prompts.LANGUAGES.get(self.language, "English"))
        try:
            resp = self.router.complete([Message.system(system),
                                         Message.user(f"Findings:\n{facts}")], None,
                                        max_tokens=2500)
        except LLMError as e:
            self.emit("agent_error", {"agent": "reporter", "error": str(e)[:300]})
            return ReportDraft(deterministic_summary(self.session, self.language), len(rows), [],
                               cmap, "deterministic (model unavailable)")
        text, kept, removed = verify_cited_text(resp.message.content or "", cites,
                                                self.session.graph)
        self.emit("report_verified", {"kept": kept, "removed": len(removed)})
        if kept == 0:
            return ReportDraft(deterministic_summary(self.session, self.language), len(rows),
                               removed, cmap, "deterministic (model output failed verification)")
        return ReportDraft(text, kept, removed, cmap, f"{resp.provider}:{resp.model}")
