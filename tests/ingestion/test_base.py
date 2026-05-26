"""Tests for glaive/ingestion/base.py — parser scaffolding."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from glaive.evidence.store import EvidenceStore
from glaive.graph.nodes import Host
from glaive.ingestion.base import Parser, ParseResult


VALID_HASH = "a" * 64


# ---- ParseResult --------------------------------------------------------------


class TestParseResult:
    def test_empty(self) -> None:
        r = ParseResult()
        assert r.nodes == []
        assert r.edges == []
        assert len(r) == 0

    def test_repr_shows_counts(self) -> None:
        r = ParseResult()
        assert "nodes=0" in repr(r)
        assert "edges=0" in repr(r)

    def test_holds_nodes(self) -> None:
        h = Host(evidence_hash=VALID_HASH, derivation="test", hostname="rd01")
        r = ParseResult(nodes=[h])
        assert len(r.nodes) == 1
        assert r.nodes[0] is h
        assert len(r) == 1

    def test_rejects_unknown_fields(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ParseResult(weird_field="oops")  # type: ignore[call-arg]


# ---- Parser abstract base ----------------------------------------------------


class _DummyParser(Parser):
    """Trivial subclass for testing the base contract."""
    source_type = "Dummy"

    def parse(self, source: Any) -> ParseResult:
        return ParseResult()


class TestParser:
    def test_parser_holds_store(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        p = _DummyParser(store)
        assert p.store is store

    def test_abstract_parse_blocks_direct_instantiation(self, tmp_path: Path) -> None:
        """A Parser subclass without parse() cannot be instantiated."""

        class BadParser(Parser):
            source_type = "Bad"
            # Forgot to implement parse()

        store = EvidenceStore(tmp_path / "store")
        with pytest.raises(TypeError, match="abstract"):
            BadParser(store)  # type: ignore[abstract]

    def test_derivation_without_path(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        p = _DummyParser(store)
        assert p._derivation() == "Dummy"

    def test_derivation_with_path(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        p = _DummyParser(store)
        d = p._derivation(Path("/some/path/Defender.evtx"))
        assert d == "Dummy Defender.evtx"
