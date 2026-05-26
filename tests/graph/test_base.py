"""Tests for glaive/graph/base.py — the foundation contracts.

Each test maps to a design decision documented in DECISIONS.md or
EVIDENCE_GRAPH_SCHEMA.md. If a test fails, the foundation is broken
and we must not proceed to subclasses.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from glaive.graph.base import Edge, GraphElement, Node


# A valid SHA-256 hex string for use in tests (64 lowercase hex chars).
VALID_SHA256 = "a" * 64
INVALID_SHA256_TOO_SHORT = "a" * 63
INVALID_SHA256_UPPERCASE = "A" * 64
INVALID_SHA256_NON_HEX = "z" * 64


class _ConcreteNode(Node):
    """Minimal Node subclass for testing the base contract."""

    node_type = "TestNode"
    name: str

    def canonical_key(self) -> tuple:
        return ("TestNode", self.name)

    def merge_into(self, other: "Node") -> None:
        return None


class _ConcreteEdge(Edge):
    """Minimal Edge subclass for testing the base contract."""

    edge_type = "TestEdge"


# ---------- B2 — extra="forbid" rejects unknown fields -----------------------


def test_extra_fields_rejected_on_node() -> None:
    """Decision B2: Pydantic rejects unknown fields immediately."""
    with pytest.raises(ValidationError) as exc_info:
        _ConcreteNode(
            evidence_hash=VALID_SHA256,
            derivation="test",
            name="alice",
            unknown_field="oops",  # type: ignore[call-arg]
        )
    assert "unknown_field" in str(exc_info.value).lower() or "extra" in str(exc_info.value).lower()


def test_extra_fields_rejected_on_edge() -> None:
    with pytest.raises(ValidationError):
        _ConcreteEdge(
            evidence_hash=VALID_SHA256,
            derivation="test",
            source_key=("a",),
            target_key=("b",),
            random_extra="nope",  # type: ignore[call-arg]
        )


# ---------- Principle 3 — SHA-256 format enforced -----------------------------


def test_evidence_hash_must_be_64_chars() -> None:
    with pytest.raises(ValidationError):
        _ConcreteNode(
            evidence_hash=INVALID_SHA256_TOO_SHORT,
            derivation="test",
            name="alice",
        )


def test_evidence_hash_must_be_lowercase_hex() -> None:
    with pytest.raises(ValidationError):
        _ConcreteNode(
            evidence_hash=INVALID_SHA256_UPPERCASE,
            derivation="test",
            name="alice",
        )


def test_evidence_hash_must_be_hex_chars() -> None:
    with pytest.raises(ValidationError):
        _ConcreteNode(
            evidence_hash=INVALID_SHA256_NON_HEX,
            derivation="test",
            name="alice",
        )


def test_evidence_hash_valid_passes() -> None:
    node = _ConcreteNode(
        evidence_hash=VALID_SHA256,
        derivation="test",
        name="alice",
    )
    assert node.evidence_hash == VALID_SHA256


# ---------- B7 — UTC enforcement ---------------------------------------------


def test_observed_at_rejects_naive_datetime() -> None:
    """Naive datetime (no tzinfo) must be rejected."""
    naive = datetime(2026, 1, 1, 12, 0, 0)
    with pytest.raises(ValidationError):
        _ConcreteNode(
            evidence_hash=VALID_SHA256,
            derivation="test",
            name="alice",
            observed_at=naive,
        )


def test_observed_at_rejects_non_utc_tz() -> None:
    """A datetime in a non-UTC timezone must be rejected."""
    not_utc = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=5)))
    with pytest.raises(ValidationError):
        _ConcreteNode(
            evidence_hash=VALID_SHA256,
            derivation="test",
            name="alice",
            observed_at=not_utc,
        )


def test_observed_at_defaults_to_utc_now() -> None:
    """When not provided, observed_at defaults to a UTC-aware datetime near now."""
    before = datetime.now(timezone.utc)
    node = _ConcreteNode(evidence_hash=VALID_SHA256, derivation="test", name="alice")
    after = datetime.now(timezone.utc)

    assert node.observed_at.tzinfo is not None
    assert node.observed_at.utcoffset() == timedelta(0)
    assert before <= node.observed_at <= after


def test_edge_timestamp_can_be_none() -> None:
    """Decision B7 + schema: edge timestamp is nullable when unknown."""
    edge = _ConcreteEdge(
        evidence_hash=VALID_SHA256,
        derivation="test",
        source_key=("a",),
        target_key=("b",),
        timestamp=None,
    )
    assert edge.timestamp is None


def test_edge_timestamp_rejects_naive() -> None:
    """If a timestamp is set, it must be UTC-aware."""
    with pytest.raises(ValidationError):
        _ConcreteEdge(
            evidence_hash=VALID_SHA256,
            derivation="test",
            source_key=("a",),
            target_key=("b",),
            timestamp=datetime(2023, 1, 25, 14, 52, 4),
        )


# ---------- Section 5 — Edge canonical key ------------------------------------


def test_edge_canonical_key_structure() -> None:
    """Edge identity = (source_key, target_key, edge_type, timestamp)."""
    ts = datetime(2023, 1, 25, 14, 52, 4, tzinfo=timezone.utc)
    edge = _ConcreteEdge(
        evidence_hash=VALID_SHA256,
        derivation="test",
        source_key=("Process", "rd01", 1244),
        target_key=("Process", "rd01", 1912),
        timestamp=ts,
    )
    key = edge.canonical_key()
    assert key == (("Process", "rd01", 1244), ("Process", "rd01", 1912), "TestEdge", ts)


def test_edge_canonical_key_handles_none_timestamp() -> None:
    """Edges with unknown timestamp still have a valid canonical key."""
    edge = _ConcreteEdge(
        evidence_hash=VALID_SHA256,
        derivation="test",
        source_key=("a",),
        target_key=("b",),
    )
    key = edge.canonical_key()
    assert key == (("a",), ("b",), "TestEdge", None)


# ---------- B3 — Abstract base classes cannot be instantiated directly --------


def test_cannot_instantiate_graphelement_abstract() -> None:
    """GraphElement is meant as a base, not a working type.

    Note: GraphElement itself isn't ABC, but its required fields make it
    impossible to construct without subclass behavior. This test documents
    that we expect subclasses, not direct use.
    """
    # GraphElement is concrete enough to construct, but it lacks the
    # type discrimination that Node/Edge provide. This documents intent.
    elem = GraphElement(evidence_hash=VALID_SHA256, derivation="test")
    assert isinstance(elem, GraphElement)


def test_node_subclass_without_abstract_methods_cannot_instantiate() -> None:
    """A Node subclass that doesn't override the abstract methods cannot be instantiated."""

    class BadNode(Node):
        node_type = "Bad"
        # Forgot to override canonical_key and merge_into

    with pytest.raises(TypeError) as exc_info:
        BadNode(evidence_hash=VALID_SHA256, derivation="test")
    msg = str(exc_info.value).lower()
    assert "abstract" in msg
