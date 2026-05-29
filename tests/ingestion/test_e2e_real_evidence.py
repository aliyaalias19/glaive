"""End-to-end test: real Defender.evtx → typed evidence graph.

This is the demo proof. Every layer of the stack we built since Day 3
participates: evidence store, EVTX adapter, Defender parser, orchestrator,
graph wrapper, AntivirusDetection node type.

Marked `integration` — requires test_evidence/Defender.evtx and is excluded
from default pytest runs (~10s for this test alone).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from glaive.evidence.store import EvidenceStore, hash_file
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.defender import DefenderEvtxParser
from glaive.ingestion.evtx_adapter import iter_evtx_events
from glaive.ingestion.orchestrator import Orchestrator


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"


@pytest.fixture(scope="module")
def populated_graph(
    tmp_path_factory, real_defender_events
) -> tuple[EvidenceGraph, EvidenceStore, str, dict]:
    """Run the orchestrator pipeline ONCE per test module against the real
    Defender.evtx.

    Consumes the session-scoped `real_defender_events` fixture from
    conftest.py so the binary EVTX is parsed only once across the entire
    test session.

    Returns:
        (graph, store, expected_hash, report) tuple for individual tests to inspect.
    """
    # Fresh store + graph for this module
    store_root = tmp_path_factory.mktemp("e2e_store")
    store = EvidenceStore(store_root)
    graph = EvidenceGraph()
    orch = Orchestrator(graph, store)
    parser = DefenderEvtxParser(store)

    # Reuse the cached parse from conftest
    events, _stats = real_defender_events

    # Drive the orchestrator through the full pipeline
    report = orch.run(parser, source_path=REAL_EVTX, parse_input=events)

    expected_hash = hash_file(REAL_EVTX)
    return graph, store, expected_hash, report


@pytest.mark.integration
@pytest.mark.skipif(not REAL_EVTX.exists(), reason="Real Defender.evtx not present.")
class TestRealPipeline:
    """End-to-end pipeline against a real Windows Defender EVTX file."""

    def test_pipeline_produces_ten_av_detection_nodes(self, populated_graph) -> None:
        """Every supported Defender event in the real file becomes one node.

        Our earlier survey counted exactly 10 supported events (1116/1117 mix).
        If this assertion fails: either the survey count changed (re-run it),
        or a stage of the pipeline is dropping/duplicating nodes.
        """
        graph, _, _, _ = populated_graph
        av_nodes = list(graph.find_nodes(node_type="AntivirusDetection"))
        assert len(av_nodes) == 10, (
            f"Expected 10 AntivirusDetection nodes from real Defender.evtx, "
            f"got {len(av_nodes)}. Pipeline stage dropping or duplicating."
        )

    def test_pipeline_skips_unsupported_events(self, populated_graph) -> None:
        """15,911 records read, 10 became nodes, 15,901 skipped.

        Verifies the parser correctly filters Event IDs not in SUPPORTED_EVENT_IDS.
        """
        _, _, _, report = populated_graph
        # Orchestrator captures parser stats — the Defender parser tracks skipped
        skipped = report.parser_stats.get("skipped_event_count", 0)
        # 15,911 total records - 10 supported events = 15,901 skipped
        assert skipped == 15_901, (
            f"Expected 15,901 skipped, got {skipped}. Either the file changed "
            f"or the SUPPORTED_EVENT_IDS filter regressed."
        )

    def test_every_node_has_correct_evidence_hash(self, populated_graph) -> None:
        """The audit-trail proof: every finding traces back to source bytes.

        This is the architectural promise GLAIVE makes. If it fails, the
        evidence_hash field somewhere lost its provenance.
        """
        graph, _, expected_hash, _ = populated_graph
        for node in graph.find_nodes(node_type="AntivirusDetection"):
            assert node.evidence_hash == expected_hash, (
                f"Node {node.canonical_key()} has hash {node.evidence_hash[:16]}..., "
                f"expected {expected_hash[:16]}.... Provenance chain broken."
            )

    def test_evidence_store_can_recover_source_bytes(self, populated_graph) -> None:
        """Closing the audit loop: given a node's evidence_hash, the original
        file content is retrievable.

        This is what judges trace down when verifying a finding.
        """
        graph, store, expected_hash, _ = populated_graph
        node = next(graph.find_nodes(node_type="AntivirusDetection"))

        # The hash on the node is in the store
        assert store.has(node.evidence_hash)

        # The recovered bytes match the original file
        recovered = store.read(node.evidence_hash)
        original = REAL_EVTX.read_bytes()
        assert recovered == original, "Recovered evidence bytes differ from source"

    def test_can_query_findings_by_threat_name(self, populated_graph) -> None:
        """The Hunter-agent's typical query: find all threats matching a pattern.

        This is the closest test to the final demo video moment — agent says
        'find all Trojan detections' and gets concrete results back.
        """
        graph, _, _, _ = populated_graph

        # Find all Trojan detections
        trojan_findings = list(
            graph.find_nodes(
                node_type="AntivirusDetection",
                predicate=lambda n: "Trojan" in (n.threat_name or ""),
            )
        )
        # We know your file has at least one Trojan:Win32/Cloxer detection
        assert len(trojan_findings) > 0, "Real file had Trojan detections; got none"

        # Each finding is fully populated
        for finding in trojan_findings:
            assert finding.threat_name is not None
            assert finding.detection_time is not None
            assert finding.host_hostname  # non-empty

    def test_orchestrator_report_reflects_real_run(self, populated_graph) -> None:
        """The report a judge would inspect: stats reflect the actual ingest."""
        _, _, expected_hash, report = populated_graph
        assert report.parser_name == "DefenderEvtxParser"
        assert report.evidence_hash == expected_hash
        assert report.nodes_added == 10
        assert report.nodes_merged == 0  # fresh graph, first run
        assert report.duration_seconds > 0
