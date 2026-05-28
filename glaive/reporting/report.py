"""Finding report — the typed output of the GLAIVE investigation.

A Finding is one committed claim with provenance. A FindingReport is the
accumulator of all such findings, and the GATE that enforces which claims
are allowed to enter.

The gate is the centerpiece of the architectural-constraint story
(Criterion 4): findings cannot be committed unless their supporting_keys
all resolve to real graph nodes, and the agent's confidence_hint is
checked against graph-derived confidence rather than trusted.

References:
  - DECISIONS.md M3 (commit_finding gate enforcement)
  - docs/EVIDENCE_GRAPH_SCHEMA.md section 4.4 (confirmed_by -> confidence)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from glaive.graph.wrapper import EvidenceGraph


# Confidence levels surfaced to findings.
ConfidenceLevel = Literal["confirmed", "suspected", "inferred", "disputed"]


# Decision outcomes for can_commit().
DecisionStatus = Literal["accepted", "rejected_missing_node", "rejected_empty_support",
                          "downgraded_confidence"]


class CommitDecision(BaseModel):
    """Outcome of evaluating whether a finding can be committed.

    Returned by FindingReport.can_commit() so the agent (or any caller) can
    see WHY a commit was accepted or rejected, not just IF it was.
    """

    model_config = ConfigDict(extra="forbid")

    status: DecisionStatus
    reason: str = ""
    # If accepted: the Finding that would be committed (or was, if commit() was called)
    finding: "Finding | None" = None
    # If confidence was downgraded: what we changed it to vs what the agent claimed
    agent_confidence_hint: ConfidenceLevel | None = None
    final_confidence: ConfidenceLevel | None = None


class Finding(BaseModel):
    """One committed forensic finding.

    Every field except finding_id and committed_at is provided by the agent;
    finding_id and committed_at are stamped at commit time.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    claim: str = Field(..., min_length=1, description="Human-readable forensic claim.")
    supporting_node_keys: list[tuple] = Field(
        default_factory=list,
        description="canonical_keys of graph nodes that support this claim.",
    )
    confidence: ConfidenceLevel = Field(..., description="Final confidence level (after gate).")
    committed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingReport(BaseModel):
    """Accumulator of committed findings.

    The gate (can_commit) enforces:
      1. At least one supporting_key must be provided
      2. Every supporting_key must resolve to a real graph node
      3. The agent's confidence_hint is checked against graph evidence,
         downgraded if the supporting evidence doesn't justify the hint
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    findings: list[Finding] = Field(default_factory=list)

    def can_commit(
        self,
        claim: str,
        supporting_node_keys: list[tuple],
        confidence_hint: ConfidenceLevel,
        graph: "EvidenceGraph",
    ) -> CommitDecision:
        """Evaluate whether this claim can be committed.

        Does NOT mutate the report. Use commit() to actually add to findings.
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

        # Rule 3: derive confidence from graph evidence
        final_confidence = self._derive_confidence(
            supporting_node_keys, confidence_hint, graph
        )

        proposed = Finding(
            claim=claim,
            supporting_node_keys=[tuple(k) for k in supporting_node_keys],
            confidence=final_confidence,
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
            )

        return CommitDecision(
            status="accepted",
            reason="All supporting nodes verified; confidence matches evidence.",
            finding=proposed,
            agent_confidence_hint=confidence_hint,
            final_confidence=final_confidence,
        )

    def commit(self, finding: Finding) -> None:
        """Append a Finding to the report.

        Callers should pass the Finding from a CommitDecision (not construct
        one directly), so the gate has already been evaluated.
        """
        self.findings.append(finding)

    def _derive_confidence(
        self,
        supporting_node_keys: list[tuple],
        agent_hint: ConfidenceLevel,
        graph: "EvidenceGraph",
    ) -> ConfidenceLevel:
        """Determine the right confidence level based on the graph evidence.

        Look at incoming/outgoing edges of the supporting nodes; aggregate
        their confidence. We never *upgrade* the agent's hint — only validate
        or downgrade.

        Rules:
          - If any supporting node has 'disputed' state in its graph context, → "disputed"
          - Else if all relevant edges are 'confirmed', → "confirmed"
          - Else if any relevant edges are 'confirmed', → at most "suspected"
          - Else → "inferred"

        The agent's hint is the ceiling. We pick min(hint, evidence-derived).
        """
        # Find any "disputed" disagreements on supporting nodes
        for key in supporting_node_keys:
            node = graph.get_node(tuple(key))
            if hasattr(node, "disagreements") and node.disagreements:
                return "disputed"

        # Look at edges touching the supporting nodes for confidence levels
        edge_confidences: list[str] = []
        for key in supporting_node_keys:
            for edge in graph.outgoing_edges(tuple(key)):
                if hasattr(edge, "confidence"):
                    edge_confidences.append(edge.confidence)
            for edge in graph.incoming_edges(tuple(key)):
                if hasattr(edge, "confidence"):
                    edge_confidences.append(edge.confidence)

        # Decide the evidence-derived confidence
        if not edge_confidences:
            evidence_confidence: ConfidenceLevel = "inferred"
        elif all(c == "confirmed" for c in edge_confidences):
            evidence_confidence = "confirmed"
        elif "confirmed" in edge_confidences or "suspected" in edge_confidences:
            evidence_confidence = "suspected"
        else:
            evidence_confidence = "inferred"

        # Take the lower of (agent hint, evidence-derived)
        rank = {"inferred": 1, "suspected": 2, "confirmed": 3, "disputed": 0}
        if rank[evidence_confidence] < rank[agent_hint]:
            return evidence_confidence
        return agent_hint

    def to_markdown(self) -> str:
        """Render the report as a human-readable markdown document.

        Used to produce the final report a judge would read.
        """
        if not self.findings:
            return "# GLAIVE Investigation Report\n\nNo findings committed.\n"

        lines = ["# GLAIVE Investigation Report", ""]
        lines.append(f"**Findings committed:** {len(self.findings)}")
        lines.append("")
        for i, f in enumerate(self.findings, 1):
            lines.append(f"## Finding {i} — `{f.confidence}`")
            lines.append("")
            lines.append(f"**Claim:** {f.claim}")
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
