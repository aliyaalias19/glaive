"""Orchestrator — wires parsers + evidence store + graph into one pipeline.

Design (DECISIONS.md O1, O2):
  O1 — Class-based: Orchestrator holds graph + store references, accumulates stats
  O2 — Orchestrator hashes files before parsing; passes hash into parser input

Usage:
    graph = EvidenceGraph()
    store = EvidenceStore(Path("./analysis/evidence_store"))
    orch = Orchestrator(graph, store)

    # Defender events from a pre-parsed dict list
    defender = DefenderEvtxParser(store)
    report = orch.run(defender, source_path=Path("./Defender.evtx"),
                                events_iterable=[{...}, ...])

    print(report)  # IngestReport(nodes_added=7, edges_added=0, ...)
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from glaive.evidence.store import EvidenceStore
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.base import Parser, ParseResult


class IngestReport(BaseModel):
    """Per-run report from an orchestrator invocation.

    Accumulates across multiple parsers if reused.
    """

    model_config = ConfigDict(extra="forbid")

    parser_name: str
    source_path: str | None = None
    evidence_hash: str | None = None
    nodes_added: int = 0
    nodes_merged: int = 0
    edges_added: int = 0
    edges_merged: int = 0
    parser_stats: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    finished_at: datetime

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def __repr__(self) -> str:
        return (
            f"IngestReport({self.parser_name}, "
            f"nodes={self.nodes_added}+{self.nodes_merged}merged, "
            f"edges={self.edges_added}+{self.edges_merged}merged, "
            f"{self.duration_seconds:.2f}s)"
        )


class Orchestrator:
    """Runs parsers against evidence and populates a graph.

    Holds references to a graph and a store. Each call to run() executes one
    parser and returns an IngestReport.
    """

    def __init__(self, graph: EvidenceGraph, store: EvidenceStore) -> None:
        self.graph = graph
        self.store = store
        self.reports: list[IngestReport] = []

    def run(
        self,
        parser: Parser,
        *,
        source_path: Path | None = None,
        parse_input: Any = None,
    ) -> IngestReport:
        """Run a parser and integrate its output into the graph.

        Args:
            parser: A Parser subclass instance bound to self.store
            source_path: Optional path to the source evidence file. If
                provided, the file is hashed and ingested into the store,
                and the resulting evidence_hash is injected into parse_input
                where appropriate.
            parse_input: The input to pass to parser.parse() — typically a
                list/dict of pre-parsed records. For Day 4, this is mandatory.
                Day 5 will add a layer where source_path alone is enough
                (parser knows how to read binary).

        Returns:
            IngestReport with stats from this run.
        """
        started = datetime.now(UTC)

        evidence_hash: str | None = None
        if source_path is not None:
            evidence_hash = self.store.ingest(source_path)

        # If parse_input is a list of dicts and we have an evidence_hash,
        # inject it into each dict (the parsers honor _evidence_hash override).
        prepared_input = self._prepare_input(parse_input, evidence_hash, parser, source_path)

        # Run the parser
        result: ParseResult = parser.parse(prepared_input)
        return self.integrate(type(parser).__name__, result, source_path=source_path,
                              evidence_hash=evidence_hash, started=started)

    def integrate(
        self,
        parser_name: str,
        result: ParseResult,
        *,
        source_path: Path | str | None = None,
        evidence_hash: str | None = None,
        started: datetime | None = None,
    ) -> IngestReport:
        """Add an already-parsed result to the graph and record an IngestReport.

        Used by run(), and directly by the multi-file pipeline, which parses
        events from many files in one pass so cross-file processes merge.
        """
        started = started or datetime.now(UTC)

        nodes_added = 0
        nodes_merged = 0
        for node in result.nodes:
            existing = self.graph.has_node(node.canonical_key())
            self.graph.add_node(node)
            if existing:
                nodes_merged += 1
            else:
                nodes_added += 1

        edges_added = 0
        edges_merged = 0
        orphan_edges = 0
        for edge in result.edges:
            existing = self.graph.has_edge_key(edge)
            try:
                self.graph.add_edge(edge)
                if existing:
                    edges_merged += 1
                else:
                    edges_added += 1
            except KeyError:
                # Endpoint not in graph. Counted (v0.1 dropped these silently).
                orphan_edges += 1

        parser_stats = self._extract_parser_stats(result)
        if orphan_edges:
            parser_stats["orphan_edges_skipped"] = orphan_edges

        report = IngestReport(
            parser_name=parser_name,
            source_path=str(source_path) if source_path else None,
            evidence_hash=evidence_hash,
            nodes_added=nodes_added,
            nodes_merged=nodes_merged,
            edges_added=edges_added,
            edges_merged=edges_merged,
            parser_stats=parser_stats,
            started_at=started,
            finished_at=datetime.now(UTC),
        )
        self.reports.append(report)
        return report

    def _prepare_input(
        self,
        parse_input: Any,
        evidence_hash: str | None,
        parser: Parser,
        source_path: Path | None = None,
    ) -> Any:
        """Inject evidence_hash and derivation into per-record dicts.

        Records that already carry "_evidence_hash" / "_derivation" keep them.
        The orchestrator injects the hash only if a source_path was provided.
        """
        if evidence_hash is None or parse_input is None:
            return parse_input

        # v0.1 built this from self.reports[-1].source_path (the PREVIOUS
        # run's file) and crashed when that run had no source_path. The
        # derivation now names the file actually being ingested.
        derivation = parser._derivation(source_path)

        def stamp(rec: dict) -> dict:
            return {
                **rec,
                "_evidence_hash": rec.get("_evidence_hash", evidence_hash),
                "_derivation": rec.get("_derivation", derivation),
            }

        # For Defender-style parsers: list of dicts
        if isinstance(parse_input, list):
            return [stamp(rec) for rec in parse_input if isinstance(rec, dict)]

        # For Volatility-style parsers: dict of plugin -> list of dicts
        if isinstance(parse_input, dict):
            out = {}
            for plugin, records in parse_input.items():
                if not isinstance(records, list):
                    out[plugin] = records
                    continue
                out[plugin] = [stamp(rec) for rec in records if isinstance(rec, dict)]
            return out

        # Anything else: pass through
        return parse_input

    def _extract_parser_stats(self, result: ParseResult) -> dict[str, Any]:
        """Extract parser-specific stats fields from the result, if any.

        Each parser may subclass ParseResult with extra fields (e.g.,
        DefenderParseResult.skipped_event_count). We capture those here for
        the report.
        """
        # Get the model_fields of the ParseResult subclass minus the base fields
        base_fields = set(ParseResult.model_fields.keys())
        all_fields = set(type(result).model_fields.keys())
        extra_fields = all_fields - base_fields - {"event_entities"}
        return {name: getattr(result, name) for name in extra_fields}

    def summary(self) -> str:
        """Human-readable summary of all runs in this orchestrator."""
        if not self.reports:
            return "No runs."
        lines = [
            f"Orchestrator summary: {len(self.reports)} run(s)",
            f"  Graph: {self.graph.node_count()} nodes, {self.graph.edge_count()} edges",
            f"  Store: {len(self.store)} evidence files",
        ]
        for r in self.reports:
            lines.append(f"  {r!r}")
        return "\n".join(lines)
