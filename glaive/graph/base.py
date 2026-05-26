"""GLAIVE evidence graph — base Node and Edge classes.

The base classes implement the universal provenance contract (Principle 3):
every node and every edge carries evidence_hash, derivation, and observed_at.

Subclasses (in nodes.py and edges.py) add type-specific fields and override
the abstract canonical_key() and merge_into() methods.

Reference: docs/EVIDENCE_GRAPH_SCHEMA.md
"""
from __future__ import annotations

from abc import abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utcnow() -> datetime:
    """Current time, tz-aware UTC. Used as default for observed_at."""
    return datetime.now(timezone.utc)


class GraphElement(BaseModel):
    """Common base for Node and Edge. Holds the universal provenance fields.

    Three fields every graph element must carry (Principle 3):
      - evidence_hash: SHA-256 of the source artifact in the content-addressed store
      - derivation:    Tool execution string identifying how this was produced
      - observed_at:   UTC datetime when our ingestion saw this

    See docs/EVIDENCE_GRAPH_SCHEMA.md section 4.1.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        frozen=False,
    )

    evidence_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 (lowercase hex) of the source artifact.",
    )
    derivation: str = Field(
        ...,
        min_length=1,
        description="Tool execution that produced this element.",
    )
    observed_at: datetime = Field(
        default_factory=_utcnow,
        description="UTC datetime of ingestion. Auto-set if not provided.",
    )

    @field_validator("observed_at")
    @classmethod
    def _require_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware UTC")
        if v.utcoffset().total_seconds() != 0:
            raise ValueError("observed_at must be UTC (offset zero)")
        return v


class Node(GraphElement):
    """Abstract base for typed graph nodes.

    Each subclass must:
      - Override canonical_key() to return its identity tuple (see schema section 5)
      - Override merge_into(other) to combine another instance into this one

    Subclasses live in nodes.py.
    """

    node_type: ClassVar[str] = ""

    @abstractmethod
    def canonical_key(self) -> tuple[Any, ...]:
        """Identity tuple for canonicalization. See schema section 5."""
        ...

    @abstractmethod
    def merge_into(self, other: "Node") -> None:
        """Merge `other` into self. `other` should have the same canonical_key()."""
        ...


class Edge(GraphElement):
    """Abstract base for typed graph edges.

    Edges connect two nodes by their canonical keys. The graph wrapper stores
    the keys; the Edge object doesn't hold node references directly.

    The timestamp field represents when the *forensic event* occurred,
    distinct from observed_at (when we ingested).
    """

    edge_type: ClassVar[str] = ""

    source_key: tuple[Any, ...] = Field(..., description="canonical_key() of source node")
    target_key: tuple[Any, ...] = Field(..., description="canonical_key() of target node")
    timestamp: datetime | None = Field(
        None,
        description="UTC time of the forensic event (None if unknown).",
    )

    @field_validator("timestamp")
    @classmethod
    def _require_utc_or_none(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return v
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware UTC")
        if v.utcoffset().total_seconds() != 0:
            raise ValueError("timestamp must be UTC (offset zero)")
        return v

    def canonical_key(self) -> tuple[Any, ...]:
        """Edge identity = (source_key, target_key, edge_type, timestamp)."""
        return (self.source_key, self.target_key, self.edge_type, self.timestamp)

    def merge_into(self, other: "Edge") -> None:
        """Default merge: do nothing. Subclasses with confirmed_by override this."""
        return None
