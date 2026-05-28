"""Tests for glaive/reporting/report.py — the finding gate.

The gate is the architectural enforcement that makes GLAIVE different from
"Claude Code with better prompts." These tests prove the gate cannot be
bypassed by the agent providing fake keys or inflated confidence hints.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.edges import Spawned
from glaive.graph.nodes import Host, Process
from glaive.graph.wrapper import EvidenceGraph
from glaive.reporting.report import (
    CommitDecision,
    Finding,
    FindingReport,
)


VALID_HASH = "a" * 64
STUN_START = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)


# =============================================================================
# Test fixtures — small graphs for gate testing
# =============================================================================


@pytest.fixture
def graph_with_confirmed_spawned() -> EvidenceGraph:
    """A 3-node graph: Host + svchost + STUN, with confirmed Spawned edge."""
    g = EvidenceGraph()

    g.add_node(Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01"))

    svchost = Process(
        evidence_hash=VALID_HASH,
        derivation="psscan",
        host_hostname="rd01",
        pid=1244,
        name="svchost.exe",
        start_time=datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc),
    )
    g.add_node(svchost)

    stun = Process(
        evidence_hash=VALID_HASH,
        derivation="psscan",
        host_hostname="rd01",
        pid=1912,
        name="STUN.exe",
        start_time=STUN_START,
    )
    g.add_node(stun)

    g.add_edge(
        Spawned(
            evidence_hash=VALID_HASH,
            derivation="pstree+evtx_4688",
            source_key=svchost.canonical_key(),
            target_key=stun.canonical_key(),
            timestamp=STUN_START,
            confirmed_by=["pstree", "evtx_4688"],  # two sources -> "confirmed"
        )
    )
    return g


@pytest.fixture
def graph_with_suspected_spawned() -> EvidenceGraph:
    """Same shape but only ONE source -> Spawned.confidence == 'suspected'."""
    g = EvidenceGraph()
    g.add_node(Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01"))
    svchost = Process(
        evidence_hash=VALID_HASH,
        derivation="psscan",
        host_hostname="rd01",
        pid=1244,
        name="svchost.exe",
        start_time=datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc),
    )
    g.add_node(svchost)
    stun = Process(
        evidence_hash=VALID_HASH,
        derivation="psscan",
        host_hostname="rd01",
        pid=1912,
        name="STUN.exe",
        start_time=STUN_START,
    )
    g.add_node(stun)
    g.add_edge(
        Spawned(
            evidence_hash=VALID_HASH,
            derivation="pstree",
            source_key=svchost.canonical_key(),
            target_key=stun.canonical_key(),
            timestamp=STUN_START,
            confirmed_by=["pstree"],  # one source -> "suspected"
        )
    )
    return g


# =============================================================================
# Finding model basics
# =============================================================================


class TestFindingModel:
    def test_minimal_construction(self) -> None:
        f = Finding(
            claim="Test claim",
            supporting_node_keys=[("Host", "rd01")],
            confidence="suspected",
        )
        assert f.claim == "Test claim"
        # auto-generated fields
        assert len(f.finding_id) > 0
        assert f.committed_at.tzinfo is not None

    def test_empty_claim_rejected(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            Finding(
                claim="",
                supporting_node_keys=[("Host", "rd01")],
                confidence="suspected",
            )

    def test_invalid_confidence_rejected(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            Finding(
                claim="X",
                supporting_node_keys=[("Host", "rd01")],
                confidence="absolutely_certain",  # type: ignore[arg-type]
            )


# =============================================================================
# THE GATE — rejection cases
# =============================================================================


class TestGateRejection:
    """The architectural promise: certain claims CANNOT pass the gate."""

    def test_empty_support_rejected(self, graph_with_confirmed_spawned) -> None:
        report = FindingReport()
        decision = report.can_commit(
            claim="STUN.exe is malicious",
            supporting_node_keys=[],
            confidence_hint="confirmed",
            graph=graph_with_confirmed_spawned,
        )
        assert decision.status == "rejected_empty_support"
        assert "at least one" in decision.reason.lower()
        assert decision.finding is None

    def test_missing_node_key_rejected(self, graph_with_confirmed_spawned) -> None:
        """The most important rejection: agent hallucinates a key not in graph."""
        report = FindingReport()
        bogus_key = ("Process", "rd01", 99999, None)
        decision = report.can_commit(
            claim="A hallucinated process was malicious",
            supporting_node_keys=[bogus_key],
            confidence_hint="confirmed",
            graph=graph_with_confirmed_spawned,
        )
        assert decision.status == "rejected_missing_node"
        assert "99999" in decision.reason or "missing" in decision.reason.lower()
        assert decision.finding is None

    def test_partial_missing_keys_still_rejected(self, graph_with_confirmed_spawned) -> None:
        """If ANY supporting key is missing, the whole commit fails."""
        report = FindingReport()
        real_key = ("Host", "rd01")
        bogus_key = ("Process", "rd01", 99999, None)
        decision = report.can_commit(
            claim="Mixed real + fake support",
            supporting_node_keys=[real_key, bogus_key],
            confidence_hint="suspected",
            graph=graph_with_confirmed_spawned,
        )
        assert decision.status == "rejected_missing_node"


# =============================================================================
# THE GATE — confidence downgrade cases
# =============================================================================


class TestConfidenceDowngrade:
    """The agent's confidence_hint is checked against evidence, not trusted."""

    def test_agent_says_confirmed_evidence_confirms_accepted(
        self, graph_with_confirmed_spawned
    ) -> None:
        """When evidence agrees, status is 'accepted'."""
        report = FindingReport()
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        decision = report.can_commit(
            claim="svchost.exe spawned STUN.exe (multi-source)",
            supporting_node_keys=[svchost_key],
            confidence_hint="confirmed",
            graph=graph_with_confirmed_spawned,
        )
        assert decision.status == "accepted"
        assert decision.final_confidence == "confirmed"

    def test_agent_says_confirmed_evidence_only_suspected_downgrades(
        self, graph_with_suspected_spawned
    ) -> None:
        """Agent claims 'confirmed' but only one source supports → downgrade to 'suspected'."""
        report = FindingReport()
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        decision = report.can_commit(
            claim="svchost.exe spawned STUN.exe (single source)",
            supporting_node_keys=[svchost_key],
            confidence_hint="confirmed",
            graph=graph_with_suspected_spawned,
        )
        assert decision.status == "downgraded_confidence"
        assert decision.agent_confidence_hint == "confirmed"
        assert decision.final_confidence == "suspected"

    def test_agent_says_suspected_evidence_suspected_accepted(
        self, graph_with_suspected_spawned
    ) -> None:
        """Agent is honest about confidence → accepted as-is."""
        report = FindingReport()
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        decision = report.can_commit(
            claim="svchost spawned STUN (single source acknowledged)",
            supporting_node_keys=[svchost_key],
            confidence_hint="suspected",
            graph=graph_with_suspected_spawned,
        )
        assert decision.status == "accepted"
        assert decision.final_confidence == "suspected"

    def test_node_with_disagreements_forces_disputed(self) -> None:
        """A supporting node with disagreements always yields 'disputed' confidence."""
        g = EvidenceGraph()
        g.add_node(Host(evidence_hash=VALID_HASH, derivation="r", hostname="rd01"))
        p = Process(
            evidence_hash=VALID_HASH,
            derivation="psscan",
            host_hostname="rd01",
            pid=1912,
            name="STUN.exe",
            start_time=STUN_START,
            disagreements={"command_line": [{"value": "evil", "source": "X"}]},
        )
        g.add_node(p)
        report = FindingReport()
        decision = report.can_commit(
            claim="claim about a disputed process",
            supporting_node_keys=[p.canonical_key()],
            confidence_hint="confirmed",
            graph=g,
        )
        assert decision.status == "downgraded_confidence"
        assert decision.final_confidence == "disputed"


# =============================================================================
# Commit flow + report rendering
# =============================================================================


class TestCommitFlow:
    def test_commit_appends_to_findings(
        self, graph_with_confirmed_spawned
    ) -> None:
        report = FindingReport()
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        decision = report.can_commit(
            claim="svchost spawned STUN",
            supporting_node_keys=[svchost_key],
            confidence_hint="confirmed",
            graph=graph_with_confirmed_spawned,
        )
        assert decision.status == "accepted"
        report.commit(decision.finding)
        assert len(report.findings) == 1

    def test_to_markdown_empty(self) -> None:
        report = FindingReport()
        md = report.to_markdown()
        assert "No findings" in md

    def test_to_markdown_with_findings(self, graph_with_confirmed_spawned) -> None:
        report = FindingReport()
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        decision = report.can_commit(
            claim="svchost spawned STUN",
            supporting_node_keys=[svchost_key],
            confidence_hint="confirmed",
            graph=graph_with_confirmed_spawned,
        )
        report.commit(decision.finding)
        md = report.to_markdown()
        assert "Finding 1" in md
        assert "confirmed" in md
        assert "svchost spawned STUN" in md
