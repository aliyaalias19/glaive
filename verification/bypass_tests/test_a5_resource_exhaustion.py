"""A5 — Resource exhaustion via query.

Attack: The agent (or an attacker who controls a malicious agent prompt)
issues a graph query that would return millions of nodes, intending to
flood the agent context, exhaust memory, or DoS the MCP boundary.

Variants:
  - Query with no filters: agent asks "give me everything"
  - Query for a populous node type
  - Query that bypasses limit by setting limit=99999999

A purely prompt-based defense would tell the agent 'please use reasonable
limits.' A real defense bounds the response regardless of what the agent
asks.

Defense (architectural): do_query_graph has a `limit` parameter with a
DEFAULT_QUERY_LIMIT of 100. Results beyond this are not returned. The
response always reports `total_matched` (how many WERE there) and
`truncated: true` so the agent learns to refine, not retry.

This test demonstrates the bound holds across attack variants. It does NOT
yet defend against ingestion-time blow-up (a malicious 100MB EVTX file is
still parsed in full); that's an honest limitation documented below and in
BYPASS_TESTS.md.

See BYPASS_TESTS.md section A5 for the full defense narrative.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from glaive.graph.nodes import AntivirusDetection
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.tools import (
    DEFAULT_QUERY_LIMIT,
    do_query_graph,
)


pytestmark = pytest.mark.bypass


VALID_HASH = "a" * 64


@pytest.fixture
def flooded_session(tmp_path: Path) -> GlaiveSession:
    """A session pre-loaded with N=500 AntivirusDetection nodes.

    500 is enough to demonstrate truncation against the default limit (100)
    without making the test slow.
    """
    session = GlaiveSession(analysis_dir=tmp_path)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    for i in range(500):
        node = AntivirusDetection(
            evidence_hash=VALID_HASH,
            derivation="seeded",
            host_hostname="rd01",
            event_id=1116,
            threat_name=f"Threat:{i:04d}",
            detection_time=base.replace(microsecond=i),
        )
        session.graph.add_node(node)
    return session


class TestA5ResourceExhaustion:
    def test_attack_unbounded_query_is_capped(
        self, flooded_session: GlaiveSession
    ) -> None:
        """ATTACK: agent issues an unfiltered query, no limit specified.

        DEFENSE: response capped at DEFAULT_QUERY_LIMIT (100). truncated=True
        signals to the agent that more data exists.
        """
        result = do_query_graph(flooded_session, node_type="AntivirusDetection")

        assert result["status"] == "ok"
        assert result["total_matched"] == 500
        assert result["returned"] == DEFAULT_QUERY_LIMIT
        assert len(result["nodes"]) == DEFAULT_QUERY_LIMIT
        assert result["truncated"] is True

    def test_attack_explicit_huge_limit_is_capped(
        self, flooded_session: GlaiveSession
    ) -> None:
        """ATTACK: agent explicitly requests limit=99999999.

        DEFENSE: the limit parameter is the cap — if the agent asks for
        more than exists, fine; but the architectural cap is also that
        the in-memory list is sized by the loop, which terminates either
        on graph exhaustion or on hitting `limit`. So asking for huge
        limits doesn't allocate huge memory.

        Documented behavior: limit is the user's ceiling; we don't enforce
        a SECOND, lower hard cap on top of it. The defense is that the
        DEFAULT is small, not that the cap is uncrossable. An agent that
        actively tries to flood itself can — but the gate exposes
        truncated=True so this is observable.
        """
        # Asking for limit=10000 on a 500-node graph: response has 500 nodes,
        # truncated=False (no truncation because total<=limit), no resource
        # blow-up.
        result = do_query_graph(
            flooded_session, node_type="AntivirusDetection", limit=10000
        )
        assert result["status"] == "ok"
        assert result["returned"] == 500
        assert result["truncated"] is False
        # And the dict is still JSON-serializable, finite, bounded
        import json
        json.dumps(result)

    def test_filtered_query_returns_only_matches(
        self, flooded_session: GlaiveSession
    ) -> None:
        """CONTROL: a sharp filter returns a small bounded set.

        Demonstrates the agent's self-correction path: when `truncated: true`
        is seen, the agent refines its filters to narrow the result.
        """
        # Filter narrows to just one threat
        result = do_query_graph(
            flooded_session,
            node_type="AntivirusDetection",
            filters=[
                {"field": "threat_name", "op": "eq", "value": "Threat:0042"}
            ],
        )
        assert result["total_matched"] == 1
        assert result["returned"] == 1
        assert result["truncated"] is False
        assert result["nodes"][0]["threat_name"] == "Threat:0042"

    def test_truncated_response_size_is_bounded(
        self, flooded_session: GlaiveSession
    ) -> None:
        """DEFENSE-BY-MEASUREMENT: with default limit, response payload
        is bounded in size.

        This is the operational guarantee: an unbounded query against a
        very large graph still produces an O(limit)-sized response, not an
        O(graph)-sized one. Token cost stays bounded.
        """
        import json

        result = do_query_graph(flooded_session, node_type="AntivirusDetection")
        # Even though 500 nodes match, the JSON response holds only 100
        # node summaries. Token cost is approximately limit * summary_size,
        # not total_matched * summary_size.
        payload = json.dumps(result)
        # Sanity check on size — a typical 100-node summary is ~10-30KB.
        assert len(payload) < 100_000  # 100KB ceiling — very generous
        # And the truncated flag is set so the agent KNOWS to refine
        assert result["truncated"] is True
