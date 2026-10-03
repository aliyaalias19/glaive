"""Finding report - the typed output of the GLAIVE investigation.

A Finding is one committed claim with provenance. A FindingReport is the
accumulator of all such findings, and the GATE that enforces which claims
are allowed to enter.

The gate is the centerpiece of the architectural-constraint story
(Criterion 4): findings cannot be committed unless their supporting_keys
all resolve to real graph nodes, every concrete entity in the claim is
present in that evidence, and the agent's confidence_hint is checked against
graph-derived confidence rather than trusted.

v0.2 adds: severity, ATT&CK techniques, author, the Skeptic's review, a
human-in-the-loop approval workflow, and save/load for the case file.

References:
  - DECISIONS.md M3 (commit_finding gate enforcement)
  - docs/EVIDENCE_GRAPH_SCHEMA.md section 4.4 (confirmed_by -> confidence)
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from glaive.reporting.grounding import check_grounding

if TYPE_CHECKING:
    from glaive.graph.wrapper import EvidenceGraph


# Confidence levels surfaced to findings.
ConfidenceLevel = Literal["confirmed", "suspected", "inferred", "disputed"]

# Decision outcomes for can_commit().
DecisionStatus = Literal["accepted", "rejected_missing_node", "rejected_empty_support",
                          "downgraded_confidence", "rejected_ungrounded_claim"]

Severity = Literal["info", "low", "medium", "high", "critical"]

# Lifecycle of a committed finding (human-in-the-loop).
FindingStatus = Literal["committed", "pending_approval", "approved", "rejected_by_analyst"]

CONFIDENCE_RANK = {"disputed": 0, "inferred": 1, "suspected": 2, "confirmed": 3}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class CommitDecision(BaseModel):
    """Outcome of evaluating whether a finding can be committed.

    Returned by FindingReport.can_commit() so the agent (or any caller) can
    see WHY a commit was accepted or rejected, not just IF it was.
    """

    model_config = ConfigDict(extra="forbid")

    status: DecisionStatus
    reason: str = ""
    # If accepted: the Finding that would be committed (or was, if commit() was called)
    finding: Finding | None = None
    # If confidence was downgraded: what we changed it to vs what the agent claimed
    agent_confidence_hint: ConfidenceLevel | None = None
    final_confidence: ConfidenceLevel | None = None
    # Which entities in the claim were / were not found in the evidence
    grounding: dict[str, Any] | None = None


class SkepticReview(BaseModel):
    """The Skeptic agent's attempt to refute a finding."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["upheld", "weakened", "refuted"]
    argument: str
    alternative_explanation: str | None = None
    reviewer: str = "skeptic"


class Finding(BaseModel):
    """One committed forensic finding.

    finding_id and committed_at are stamped at commit time; everything else
    comes from the proposer and the gate.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    claim: str = Field(..., min_length=1, description="Human-readable forensic claim.")
    supporting_node_keys: list[tuple] = Field(
        default_factory=list,
        description="canonical_keys of graph nodes that support this claim.",
    )
    confidence: ConfidenceLevel = Field(..., description="Final confidence level (after gate).")
    committed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: Severity = "medium"
    mitre_techniques: list[str] = Field(default_factory=list, description="e.g. ['T1562.001']")
    author: str = Field("agent", description="Who proposed it: agent name or rule id.")
    rationale: str | None = None
    status: FindingStatus = "committed"
    reviewed_by: str | None = None
    review_note: str | None = None
    skeptic: SkepticReview | None = None
    grounding: dict[str, Any] | None = None
    approval_reason: str | None = None  # why an analyst must approve it

    @property
    def short_id(self) -> str:
        return self.finding_id[:8]


# Claims that clear something ("no malicious activity", "a false positive",
# "the host is clean"). Exonerating a host is what an attacker who planted
# instructions in the logs wants most, and a model cannot be sure of an
# absence anyway, so when an AI says so an analyst must approve it.
_EXONERATION = re.compile(
    r"\b(no|not\s+any|nothing)\s+(?:\w+\s+){0,2}(malicious|suspicious|attack|attacker|threat|"
    r"compromise|intrusion)"
    r"|\b(is|are|was|were|appears?\s+to\s+be|looks?|seems?)\s+(clean|benign|legitimate|"
    r"harmless|safe)\b"
    r"|\bfalse\s+positives?\b|\bnot\s+(malicious|compromised|an?\s+attack)\b"
    r"|\bauthori[sz]ed\s+(red[\s-]?team|test|pen(etration)?\s*test)"
    r"|未发现(任何)?(恶意|可疑|攻击|入侵)|(没有|无)(恶意|可疑)(活动|行为)|误报|主机(是)?(安全|干净)的",
    re.IGNORECASE)


def is_exoneration(claim: str) -> bool:
    return _EXONERATION.search(claim) is not None


class FindingReport(BaseModel):
    """Accumulator of committed findings.

    The gate (can_commit) enforces:
      1. At least one supporting_key must be provided
      2. Every supporting_key must resolve to a real graph node
      3. Every concrete entity in the claim must be in that evidence
      4. The agent's confidence_hint is checked against graph evidence,
         downgraded if the supporting evidence doesn't justify the hint
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    findings: list[Finding] = Field(default_factory=list)
    # Severities that need an analyst's approval before they count as final.
    approval_required_for: set[str] = Field(default_factory=lambda: {"high", "critical"})
    _listeners: list[Callable[[str, Finding], None]] = PrivateAttr(default_factory=list)

    # ---- events -----------------------------------------------------------------

    def subscribe(self, fn: Callable[[str, Finding], None]) -> None:
        """Register fn(event, finding); events: committed, reviewed, skeptic."""
        self._listeners.append(fn)

    def _emit(self, event: str, finding: Finding) -> None:
        for fn in list(self._listeners):
            try:
                fn(event, finding)
            except Exception:  # a broken listener must never break the gate
                pass

    # ---- the gate ---------------------------------------------------------------

    def can_commit(
        self,
        claim: str,
        supporting_node_keys: list[tuple],
        confidence_hint: ConfidenceLevel,
        graph: EvidenceGraph,
        **finding_fields: Any,
    ) -> CommitDecision:
        """Evaluate whether this claim can be committed.

        Does NOT mutate the report. Use commit() to actually add to findings.
        Extra keyword arguments (severity, mitre_techniques, author, rationale)
        are carried onto the proposed Finding.
        """
        # Rule 1: must have at least one supporting key
        if not supporting_node_keys:
            return CommitDecision(
                status="rejected_empty_support",
                reason="A finding must reference at least one supporting graph node.",
            )

        # Rule 2: every key must resolve to a node
        missing = [k for k in supporting_node_keys if not graph.has_node(tuple(k))]
        if missing:
            return CommitDecision(
                status="rejected_missing_node",
                reason=(
                    f"{len(missing)} supporting node key(s) do not exist in the graph. "
                    f"First missing: {missing[0]}"
                ),
            )

        # Rule 3: every concrete entity in the claim (IP, path, hash, threat
        # name, ...) must appear in the cited nodes or their 1-hop neighbours.
        grounding = check_grounding(claim, graph, [tuple(k) for k in supporting_node_keys])
        if not grounding.ok:
            return CommitDecision(
                status="rejected_ungrounded_claim",
                reason=(
                    "The claim names things that are not in the cited evidence: "
                    f"{grounding.to_dict()['ungrounded']}. Cite the nodes that "
                    "contain them, or remove them from the claim."
                ),
                grounding=grounding.to_dict(),
            )

        # Rule 4: derive confidence from graph evidence
        final_confidence = self._derive_confidence(supporting_node_keys, confidence_hint, graph)

        proposed = Finding(
            claim=claim,
            supporting_node_keys=[tuple(k) for k in supporting_node_keys],
            confidence=final_confidence,
            grounding=grounding.to_dict(),
            **finding_fields,
        )

        if final_confidence != confidence_hint:
            return CommitDecision(
                status="downgraded_confidence",
                reason=(
                    f"Agent claimed '{confidence_hint}' but graph evidence supports "
                    f"only '{final_confidence}'. Finding accepted at the lower level."
                ),
                finding=proposed,
                agent_confidence_hint=confidence_hint,
                final_confidence=final_confidence,
                grounding=grounding.to_dict(),
            )

        return CommitDecision(
            status="accepted",
            reason="All supporting nodes verified; confidence matches evidence.",
            finding=proposed,
            agent_confidence_hint=confidence_hint,
            final_confidence=final_confidence,
            grounding=grounding.to_dict(),
        )

    def commit(self, finding: Finding) -> None:
        """Append a Finding to the report.

        Callers should pass the Finding from a CommitDecision (not construct
        one directly), so the gate has already been evaluated. Findings whose
        severity needs approval enter 'pending_approval'.
        """
        if finding.status == "committed" and finding.severity in self.approval_required_for:
            finding.status = "pending_approval"
            finding.approval_reason = f"{finding.severity} severity"
        elif finding.status == "committed" and not finding.author.startswith("rule:") \
                and is_exoneration(finding.claim):
            finding.status = "pending_approval"
            finding.approval_reason = ("clears activity as benign: an analyst must confirm "
                                       "what a model reports as absent or harmless")
        self.findings.append(finding)
        self._emit("committed", finding)

    def _derive_confidence(
        self,
        supporting_node_keys: list[tuple],
        agent_hint: ConfidenceLevel,
        graph: EvidenceGraph,
    ) -> ConfidenceLevel:
        """Determine the right confidence level based on the graph evidence.

        Look at incoming/outgoing edges of the supporting nodes; aggregate
        their confidence. We never *upgrade* the agent's hint - only validate
        or downgrade.

        Rules:
          - If any supporting node has 'disputed' state in its graph context, -> "disputed"
          - Else if all relevant edges are 'confirmed', -> "confirmed"
          - Else if any relevant edges are 'confirmed', -> at most "suspected"
          - Else -> "inferred"

        The agent's hint is the ceiling. We pick min(hint, evidence-derived).
        """
        for key in supporting_node_keys:
            node = graph.get_node(tuple(key))
            if getattr(node, "disagreements", None):
                return "disputed"

        edge_confidences: list[str] = []
        for key in supporting_node_keys:
            for edge in graph.outgoing_edges(tuple(key)):
                if hasattr(edge, "confidence"):
                    edge_confidences.append(edge.confidence)
            for edge in graph.incoming_edges(tuple(key)):
                if hasattr(edge, "confidence"):
                    edge_confidences.append(edge.confidence)

        if not edge_confidences:
            evidence_confidence: ConfidenceLevel = "inferred"
        elif all(c == "confirmed" for c in edge_confidences):
            evidence_confidence = "confirmed"
        elif "confirmed" in edge_confidences or "suspected" in edge_confidences:
            evidence_confidence = "suspected"
        else:
            evidence_confidence = "inferred"

        if CONFIDENCE_RANK[evidence_confidence] < CONFIDENCE_RANK[agent_hint]:
            return evidence_confidence
        return agent_hint

    # ---- review (Skeptic agent + human analyst) ---------------------------------

    def get(self, finding_id: str) -> Finding:
        """Find by full id or by the 8-character short id."""
        for f in self.findings:
            if f.finding_id == finding_id or f.short_id == finding_id:
                return f
        raise KeyError(finding_id)

    def apply_skeptic(self, finding_id: str, review: SkepticReview) -> Finding:
        """Record the Skeptic's review. The Skeptic can only lower confidence,
        never raise it.

        A refuted model finding is marked disputed. A rule finding states a
        fact (the rule fired on that event), so a refutation cannot make it
        less true; it is sent to an analyst instead, with the Skeptic's
        argument. This also means a Skeptic fooled by text planted in the logs
        cannot quietly discredit every deterministic finding."""
        f = self.get(finding_id)
        f.skeptic = review
        if review.verdict == "refuted" and f.author.startswith("rule:"):
            if f.status == "committed":
                f.status = "pending_approval"
            f.approval_reason = "the Skeptic argues this is benign; an analyst decides"
        elif review.verdict == "refuted":
            f.confidence = "disputed"
        elif review.verdict == "weakened" and f.confidence == "confirmed":
            f.confidence = "suspected"
        self._emit("skeptic", f)
        return f

    def review(
        self,
        finding_id: str,
        approve: bool,
        reviewer: str,
        note: str | None = None,
        override_confidence: ConfidenceLevel | None = None,
    ) -> Finding:
        """An analyst approves or rejects a finding. An override may only LOWER
        confidence: analysts can be more sceptical than the evidence, never less."""
        f = self.get(finding_id)
        if override_confidence is not None:
            if CONFIDENCE_RANK[override_confidence] > CONFIDENCE_RANK[f.confidence]:
                raise ValueError("An analyst override cannot raise confidence above the evidence.")
            f.confidence = override_confidence
        f.status = "approved" if approve else "rejected_by_analyst"
        f.reviewed_by = reviewer
        f.review_note = note
        self._emit("reviewed", f)
        return f

    def pending(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "pending_approval"]

    def final_findings(self) -> list[Finding]:
        """Findings that count in the final report (not pending, not rejected)."""
        return [f for f in self.findings if f.status in ("committed", "approved")]

    def sorted_findings(self) -> list[Finding]:
        """Most severe first, then most confident, then oldest."""
        return sorted(
            self.findings,
            key=lambda f: (-SEVERITY_RANK[f.severity], -CONFIDENCE_RANK[f.confidence],
                           f.committed_at),
        )

    # ---- persistence ------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        from glaive.graph.wrapper import encode_key

        out = []
        for f in self.findings:
            d = f.model_dump(mode="json", exclude={"supporting_node_keys"})
            d["supporting_node_keys"] = [encode_key(tuple(k)) for k in f.supporting_node_keys]
            out.append(d)
        return {"findings": out, "approval_required_for": sorted(self.approval_required_for)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FindingReport:
        from glaive.graph.wrapper import decode_key

        rep = cls(approval_required_for=set(data.get("approval_required_for", ["high", "critical"])))
        for d in data.get("findings", []):
            d = dict(d)
            d["supporting_node_keys"] = [decode_key(k) for k in d.get("supporting_node_keys", [])]
            rep.findings.append(Finding.model_validate(d))
        return rep

    # ---- rendering --------------------------------------------------------------

    def to_markdown(self) -> str:
        """Render the report as a human-readable markdown document."""
        if not self.findings:
            return "# GLAIVE Investigation Report\n\nNo findings committed.\n"

        lines = ["# GLAIVE Investigation Report", ""]
        lines.append(f"**Findings committed:** {len(self.findings)}")
        lines.append("")
        for i, f in enumerate(self.sorted_findings(), 1):
            lines.append(f"## Finding {i} - `{f.confidence}` - {f.severity.upper()}")
            lines.append("")
            lines.append(f"**Claim:** {f.claim}")
            lines.append("")
            lines.append(f"**Status:** {f.status} | **Author:** {f.author} | "
                         f"**ID:** `{f.short_id}`")
            lines.append("")
            if f.mitre_techniques:
                lines.append(f"**ATT&CK:** {', '.join(f.mitre_techniques)}")
                lines.append("")
            if f.rationale:
                lines.append(f"**Rationale:** {f.rationale}")
                lines.append("")
            if f.skeptic:
                lines.append(f"**Skeptic ({f.skeptic.verdict}):** {f.skeptic.argument}")
                lines.append("")
            lines.append(f"**Committed:** {f.committed_at.isoformat()}")
            lines.append("")
            lines.append(f"**Supporting evidence:** {len(f.supporting_node_keys)} node(s)")
            for key in f.supporting_node_keys:
                lines.append(f"  - `{key}`")
            lines.append("")
        return "\n".join(lines)


# Resolve forward references after FindingReport is defined
CommitDecision.model_rebuild()
