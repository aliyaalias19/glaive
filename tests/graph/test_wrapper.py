"""End-to-end tests for the EvidenceGraph wrapper.

These tests construct real (small) graphs representing actual SRL findings
and verify the full ingestion + query pipeline works.

If these pass, the entire base+nodes+edges+wrapper stack is functional.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from glaive.graph.edges import Spawned, Wrote
from glaive.graph.nodes import File, Host, Process
from glaive.graph.wrapper import EvidenceGraph


VALID_HASH = "a" * 64


# =============================================================================
# Basic graph mechanics
# =============================================================================


class TestEvidenceGraphBasics:
    """W1, W2, W3 — fundamentals."""

    def test_empty_graph(self) -> None:
        g = EvidenceGraph()
        assert g.node_count() == 0
        assert g.edge_count() == 0

    def test_add_single_node(self) -> None:
        g = EvidenceGraph()
        h = Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01")
        result = g.add_node(h)
        assert g.node_count() == 1
        assert result is h

    def test_get_node_by_key(self) -> None:
        g = EvidenceGraph()
        h = Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01")
        g.add_node(h)
        retrieved = g.get_node(h.canonical_key())
        assert retrieved is h

    def test_get_missing_node_raises(self) -> None:
        g = EvidenceGraph()
        with pytest.raises(KeyError):
            g.get_node(("Host", "nonexistent"))

    def test_has_node(self) -> None:
        g = EvidenceGraph()
        h = Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01")
        g.add_node(h)
        assert g.has_node(h.canonical_key()) is True
        assert g.has_node(("Host", "nonexistent")) is False

    def test_repr(self) -> None:
        g = EvidenceGraph()
        assert "0" in repr(g)
        g.add_node(Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01"))
        assert "1" in repr(g)


# =============================================================================
# Auto-merge semantics (W2)
# =============================================================================


class TestAutoMerge:
    """W2: adding a node with an existing canonical_key triggers merge_into."""

    def test_add_same_key_merges(self) -> None:
        """A second Host observation with same identity merges, doesn't duplicate."""
        g = EvidenceGraph()
        guid = "12345678-1234-1234-1234-1234567890ab"

        h1 = Host(
            evidence_hash=VALID_HASH,
            derivation="recmd SYSTEM",
            hostname="rd01",
            machine_guid=guid,
        )
        g.add_node(h1)

        # Second ingestion of the same host with extra info
        h2 = Host(
            evidence_hash=VALID_HASH,
            derivation="vol windows.info",
            hostname="rd01",
            machine_guid=guid,
            os_version="Windows Server 2022",
        )
        result = g.add_node(h2)

        # Only one host in graph
        assert g.node_count() == 1
        # Returned object is the merged-into one (the first one)
        assert result is h1
        # h1 now has the os_version from h2 (filled the null)
        assert h1.os_version == "Windows Server 2022"

    def test_add_process_merges_observed_by(self) -> None:
        """Two ingestions of the same Process merge their observed_by lists."""
        g = EvidenceGraph()
        start_ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)

        p1 = Process(
            evidence_hash=VALID_HASH,
            derivation="vol windows.psscan",
            host_hostname="rd01",
            pid=1912,
            name="STUN.exe",
            start_time=start_ts,
            observed_by=["psscan"],
        )
        g.add_node(p1)

        p2 = Process(
            evidence_hash=VALID_HASH,
            derivation="vol windows.pslist",
            host_hostname="rd01",
            pid=1912,
            name="STUN.exe",
            start_time=start_ts,
            observed_by=["pslist"],
        )
        g.add_node(p2)

        # Single process node, observed_by union
        assert g.node_count() == 1
        merged = g.get_node(p1.canonical_key())
        assert sorted(merged.observed_by) == sorted(["psscan", "pslist"])


# =============================================================================
# Endpoint discipline (W4)
# =============================================================================


class TestEndpointDiscipline:
    """W4: edges must reference nodes that exist."""

    def test_add_edge_with_missing_source_raises(self) -> None:
        g = EvidenceGraph()
        target = Process(
            evidence_hash=VALID_HASH,
            derivation="psscan",
            host_hostname="rd01",
            pid=1912,
            name="STUN.exe",
        )
        g.add_node(target)

        # source_key references a node we never added
        bogus_source = ("Process", "rd01", 9999, None)
        edge = Spawned(
            evidence_hash=VALID_HASH,
            derivation="pstree",
            source_key=bogus_source,
            target_key=target.canonical_key(),
        )
        with pytest.raises(KeyError, match="source node"):
            g.add_edge(edge)

    def test_add_edge_with_missing_target_raises(self) -> None:
        g = EvidenceGraph()
        source = Process(
            evidence_hash=VALID_HASH,
            derivation="psscan",
            host_hostname="rd01",
            pid=1244,
            name="svchost.exe",
        )
        g.add_node(source)

        bogus_target = ("Process", "rd01", 9999, None)
        edge = Spawned(
            evidence_hash=VALID_HASH,
            derivation="pstree",
            source_key=source.canonical_key(),
            target_key=bogus_target,
        )
        with pytest.raises(KeyError, match="target node"):
            g.add_edge(edge)


# =============================================================================
# The SRL STUN.exe demo case — end-to-end proof
# =============================================================================


class TestSrlStunExeCase:
    """End-to-end test that constructs a real 3-node graph for the SRL
    finding 'svchost.exe (PID 1244) spawned STUN.exe (PID 1912) at 14:52:04',
    and verifies every query method works.

    This is the proof that the entire stack (base + nodes + edges + wrapper)
    works end-to-end.
    """

    @pytest.fixture
    def graph(self) -> EvidenceGraph:
        """Build the 3-node SRL graph: Host -> Process(svchost) -> Spawned -> Process(STUN)."""
        g = EvidenceGraph()
        spawn_ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)

        # Host
        rd01 = Host(
            evidence_hash=VALID_HASH,
            derivation="recmd SYSTEM",
            hostname="rd01",
            os_version="Windows Server 2022",
        )
        g.add_node(rd01)

        # Parent process: svchost.exe PID 1244
        svchost_start = datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc)
        svchost = Process(
            evidence_hash=VALID_HASH,
            derivation="vol windows.psscan",
            host_hostname="rd01",
            pid=1244,
            name="svchost.exe",
            image_path="C:\\Windows\\System32\\svchost.exe",
            start_time=svchost_start,
            observed_by=["psscan", "pslist"],
        )
        g.add_node(svchost)

        # Child process: STUN.exe PID 1912
        stun = Process(
            evidence_hash=VALID_HASH,
            derivation="vol windows.psscan",
            host_hostname="rd01",
            pid=1912,
            name="STUN.exe",
            image_path="C:\\Windows\\System32\\STUN.exe",
            parent_pid=1244,
            start_time=spawn_ts,
            observed_by=["psscan", "pslist"],
        )
        g.add_node(stun)

        # Spawned edge
        spawn_edge = Spawned(
            evidence_hash=VALID_HASH,
            derivation="vol windows.pstree + evtx_4688",
            source_key=svchost.canonical_key(),
            target_key=stun.canonical_key(),
            timestamp=spawn_ts,
            confirmed_by=["pstree", "evtx_4688"],
        )
        g.add_edge(spawn_edge)

        return g

    def test_node_count_correct(self, graph: EvidenceGraph) -> None:
        assert graph.node_count() == 3
        assert graph.edge_count() == 1

    def test_find_nodes_by_type(self, graph: EvidenceGraph) -> None:
        hosts = list(graph.find_nodes(node_type="Host"))
        processes = list(graph.find_nodes(node_type="Process"))
        assert len(hosts) == 1
        assert len(processes) == 2
        assert {p.name for p in processes} == {"svchost.exe", "STUN.exe"}

    def test_find_nodes_with_predicate(self, graph: EvidenceGraph) -> None:
        """Find processes matching STUN.exe."""
        stuns = list(
            graph.find_nodes(
                node_type="Process",
                predicate=lambda p: p.name == "STUN.exe",
            )
        )
        assert len(stuns) == 1
        assert stuns[0].pid == 1912

    def test_outgoing_edges_from_svchost(self, graph: EvidenceGraph) -> None:
        """svchost.exe should have one outgoing Spawned edge."""
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        edges = list(graph.outgoing_edges(svchost_key))
        assert len(edges) == 1
        assert edges[0].edge_type == "Spawned"
        assert edges[0].confidence == "confirmed"

    def test_incoming_edges_to_stun(self, graph: EvidenceGraph) -> None:
        """STUN.exe should have one incoming Spawned edge."""
        stun_key = ("Process", "rd01", 1912, datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc))
        edges = list(graph.incoming_edges(stun_key))
        assert len(edges) == 1
        assert edges[0].edge_type == "Spawned"

    def test_query_the_srl_finding(self, graph: EvidenceGraph) -> None:
        """The full schema-promised query: 'who spawned STUN.exe?'"""
        # Find STUN.exe
        stuns = list(
            graph.find_nodes(
                node_type="Process",
                predicate=lambda p: p.name == "STUN.exe",
            )
        )
        assert len(stuns) == 1
        stun = stuns[0]

        # Find incoming Spawned edges
        incoming = list(graph.incoming_edges(stun.canonical_key(), edge_type="Spawned"))
        assert len(incoming) == 1

        # Trace back to parent
        parent_key = incoming[0].source_key
        parent = graph.get_node(parent_key)
        assert parent.name == "svchost.exe"
        assert parent.pid == 1244

        # The finding has corroboration
        assert incoming[0].confidence == "confirmed"
        assert "pstree" in incoming[0].confirmed_by
        assert "evtx_4688" in incoming[0].confirmed_by

    def test_edge_filtering_by_type(self, graph: EvidenceGraph) -> None:
        """outgoing_edges with a non-matching type filter returns nothing."""
        svchost_key = ("Process", "rd01", 1244, datetime(2023, 1, 25, 8, 0, 0, tzinfo=timezone.utc))
        wrote_edges = list(graph.outgoing_edges(svchost_key, edge_type="Wrote"))
        assert wrote_edges == []
