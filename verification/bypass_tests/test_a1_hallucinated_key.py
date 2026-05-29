"""A1 — Hallucinated supporting_key.

Attack: The agent commits a finding citing a graph node that does not exist.

This is the most basic attack against the gate. The agent's reasoning step
produces a canonical_key that looks plausible (right shape, right node type)
but references an entity that was never observed by any tool. A purely
prompt-based defense would say 'please don't make up evidence'; the gate
verifies graph membership by construction.

Defense (architectural): FindingReport.can_commit() calls
graph.has_node(canonical_key) for each supporting key. Missing keys produce
status='rejected_missing_node' with the offending key in the response.
The agent CANNOT bypass this by re-phrasing — the lookup is a graph
operation, not a text comparison.

See BYPASS_TESTS.md section A1 for the full defense narrative.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.tools import do_commit_finding


pytestmark = pytest.mark.bypass


@pytest.fixture
def session(tmp_path: Path) -> GlaiveSession:
    return GlaiveSession(analysis_dir=tmp_path)


class TestA1HallucinatedKey:
    def test_attack_plausible_process_key_rejected(self, session: GlaiveSession) -> None:
        """ATTACK: agent invents a Process key that looks valid but was never observed.

        DEFENSE: graph.has_node() returns False; gate rejects with the missing key.
        """
        # The attacker (or hallucinating agent) constructs a plausible-looking key:
        # right tuple shape, plausible PID, plausible hostname.
        fabricated_key = ["Process", "rd01", 1912, None]

        result = do_commit_finding(
            session,
            claim="STUN.exe was the lateral-movement payload",
            supporting_node_keys=[fabricated_key],
            confidence_hint="confirmed",
        )

        # DEFENSE: rejection is structured and identifies the offending key.
        assert result["status"] == "rejected"
        assert result["decision"] == "rejected_missing_node"
        assert result["committed"] is False
        assert "1912" in result["reason"] or "missing" in result["reason"].lower()

        # The report stays empty — no fabricated finding leaked in.
        assert session.report.findings == []

    def test_attack_partial_real_keys_still_rejected(self, session: GlaiveSession) -> None:
        """ATTACK: mix real and fake keys to try to slip the fake one through.

        DEFENSE: gate checks ALL keys; one missing key rejects the whole commit.
        """
        from datetime import datetime, timezone
        from glaive.graph.nodes import Host

        # One real node in the graph
        real_host = Host(
            evidence_hash="a" * 64,
            derivation="test",
            hostname="rd01",
        )
        session.graph.add_node(real_host)
        real_key = list(real_host.canonical_key())

        # Mix with a fake one
        fake_key = ["Process", "rd01", 99999, None]

        result = do_commit_finding(
            session,
            claim="Real evidence + fake evidence",
            supporting_node_keys=[real_key, fake_key],
            confidence_hint="suspected",
        )

        # DEFENSE: even partial fakes are rejected — atomicity protects the gate.
        assert result["status"] == "rejected"
        assert result["decision"] == "rejected_missing_node"
        assert session.report.findings == []

    def test_attack_rephrasing_does_not_help(self, session: GlaiveSession) -> None:
        """ATTACK: agent retries the same fake claim with a different phrasing,
        hoping the gate is fooled by natural-language variation.

        DEFENSE: the gate is a graph operation. Rephrasing the *claim text*
        does not change which keys exist in the graph.
        """
        fake_key = ["Process", "rd01", 9999, None]

        # Attempt 1
        r1 = do_commit_finding(
            session, "Process 9999 was malicious",
            [fake_key], "confirmed",
        )
        # Attempt 2 — same key, different prose
        r2 = do_commit_finding(
            session, "Evidence strongly suggests PID 9999 was the attacker",
            [fake_key], "suspected",
        )
        # Attempt 3 — even more cautious phrasing
        r3 = do_commit_finding(
            session, "There may be reason to investigate PID 9999 further",
            [fake_key], "inferred",
        )

        # DEFENSE: all three rejected. The gate doesn't care about the claim text;
        # it cares whether the supporting node exists.
        for r in (r1, r2, r3):
            assert r["status"] == "rejected"
            assert r["decision"] == "rejected_missing_node"

        assert session.report.findings == []
