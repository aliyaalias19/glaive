"""Base classes shared by all evidence parsers.

A parser takes a source file (or pre-parsed input) and produces a
ParseResult containing nodes and edges to be added to the EvidenceGraph.

Parser architecture (DECISIONS.md P1):
  - Each parser is a class with __init__(store: EvidenceStore)
  - The parse() method returns a ParseResult
  - Parsers do NOT add to a graph directly — that's the orchestrator's job
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from glaive.evidence.store import EvidenceStore
from glaive.graph.base import Edge, Node


class ParseResult(BaseModel):
    """The output of a parser's parse() method.

    Contains nodes and edges to be ingested into the EvidenceGraph by an
    orchestrator. Parsers never touch a graph directly — they produce data,
    and a higher layer integrates it.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.nodes) + len(self.edges)

    def __repr__(self) -> str:
        return f"ParseResult(nodes={len(self.nodes)}, edges={len(self.edges)})"


class Parser(ABC):
    """Abstract base for all evidence parsers.

    Subclasses must:
      - Set source_type ClassVar (e.g., "Defender EVTX", "Volatility psscan")
      - Implement parse() that returns a ParseResult
      - Use self.store.ingest(...) to get the evidence_hash for produced nodes/edges
    """

    source_type: str = ""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    @abstractmethod
    def parse(self, source: Any) -> ParseResult:
        """Parse `source` (interpretation depends on the parser).

        Returns a ParseResult containing typed nodes and edges.
        """
        ...

    def _derivation(self, source_path: Path | None = None) -> str:
        """Build a standard derivation string for nodes/edges this parser produces.

        Format: '<source_type> <source_path>@<short_hash>'
        e.g., 'Defender EVTX Defender.evtx@a3f29b...'
        """
        if source_path is None:
            return self.source_type
        return f"{self.source_type} {source_path.name}"
