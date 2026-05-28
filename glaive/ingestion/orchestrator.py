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

from datetime import datetime, timezone
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
        started = datetime.now(timezone.utc)

        evidence_hash: str | None = None
        if source_path is not None:
            evidence_hash = self.store.ingest(source_path)

        # If parse_input is a list of dicts and we have an evidence_hash,
        # inject it into each dict (the parsers honor _evidence_hash override).
        prepared_input = self._prepare_input(parse_input, evidence_hash, parser)

        # Run the parser
        result: ParseResult = parser.parse(prepared_input)

        # Integrate nodes
        nodes_added = 0
        nodes_merged = 0
        for node in result.nodes:
            existing = self.graph.has_node(node.canonical_key())
            self.graph.add_node(node)
            if existing:
                nodes_merged += 1
            else:
                nodes_added += 1

        # Integrate edges
        edges_added = 0
        edges_merged = 0
        for edge in result.edges:
            existing = self.graph._graph.has_edge(
                edge.source_key, edge.target_key, key=edge.canonical_key()
            )
            try:
                self.graph.add_edge(edge)
                if existing:
                    edges_merged += 1
                else:
                    edges_added += 1
            except KeyError:
                # endpoint not in graph; skip this edge
                # (parsers should not produce orphan edges, but be defensive)
                pass

        # Extract parser-specific stats from result if available (e.g., DefenderParseResult)
        parser_stats = self._extract_parser_stats(result)

        report = IngestReport(
            parser_name=type(parser).__name__,
            source_path=str(source_path) if source_path else None,
            evidence_hash=evidence_hash,
            nodes_added=nodes_added,
            nodes_merged=nodes_merged,
            edges_added=edges_added,
            edges_merged=edges_merged,
            parser_stats=parser_stats,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
        )
        self.reports.append(report)
        return report

    def _prepare_input(
        self, parse_input: Any, evidence_hash: str | None, parser: Parser
    ) -> Any:
        """Inject evidence_hash into per-record dicts where appropriate.

        Today the convention is: records with an "_evidence_hash" key override
        the parser default. The orchestrator injects this if a source_path
        was provided.
        """
        if evidence_hash is None or parse_input is None:
            return parse_input

        derivation = parser._derivation(Path(self.reports[-1].source_path) if self.reports else None)

        # For Defender-style parsers: list of dicts
        if isinstance(parse_input, list):
            return [
                {**rec, "_evidence_hash": rec.get("_evidence_hash", evidence_hash),
                 "_derivation": rec.get("_derivation", parser._derivation())}
                for rec in parse_input
                if isinstance(rec, dict)
            ]

        # For Volatility-style parsers: dict of plugin -> list of dicts
        if isinstance(parse_input, dict):
            out = {}
            for plugin, records in parse_input.items():
                if not isinstance(records, list):
                    out[plugin] = records
                    continue
                out[plugin] = [
                    {**rec, "_evidence_hash": rec.get("_evidence_hash", evidence_hash),
                     "_derivation": rec.get("_derivation", parser._derivation())}
                    for rec in records
                    if isinstance(rec, dict)
                ]
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
        extra_fields = all_fields - base_fields
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
