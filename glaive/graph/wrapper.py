"""GLAIVE evidence graph wrapper — the typed graph that holds nodes and edges.

Backed by networkx.MultiDiGraph. Provides:
  - Type-aware add/merge semantics (auto-merge on canonical_key collision)
  - Pythonic query API (returns Node/Edge objects, not raw NetworkX tuples)
  - Strict endpoint checking (raises if edge points to a missing node)

Design decisions:
  W1 — Node ID = node.canonical_key() tuple
  W2 — add_node auto-merges if key already exists
  W3 — Edge stored with edge.canonical_key() as the multigraph edge key
  W4 — Missing endpoint nodes raise KeyError (caller adds first)
  W5 — Query API returns objects, optionally filtered by type / predicate
"""
from __future__ import annotations

from typing import Any, Callable, Iterator

import networkx as nx

from glaive.graph.base import Edge, Node


class EvidenceGraph:
    """Typed evidence graph backed by networkx.MultiDiGraph.

    Use add_node / add_edge for ingestion. Use find_nodes,
    outgoing_edges, incoming_edges for queries.

    Reference: docs/EVIDENCE_GRAPH_SCHEMA.md.
    """

    def __init__(self) -> None:
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()

    # ---- ingestion -----------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        """Add a node to the graph, or merge into an existing one if the
        canonical_key already exists.

        Returns the resulting node (either the newly-added one, or the
        existing one after merging).

        W2: auto-merge semantics.
        """
        key = node.canonical_key()
        if self._graph.has_node(key):
            existing: Node = self._graph.nodes[key]["data"]
            existing.merge_into(node)
            return existing
        self._graph.add_node(key, data=node)
        return node

    def add_edge(self, edge: Edge) -> Edge:
        """Add an edge to the graph, or merge into an existing one if the
        canonical_key already exists.

        Raises KeyError if source_key or target_key references a node not
        in the graph (W4).
        """
        if not self._graph.has_node(edge.source_key):
            raise KeyError(
                f"Cannot add edge: source node {edge.source_key} not in graph"
            )
        if not self._graph.has_node(edge.target_key):
            raise KeyError(
                f"Cannot add edge: target node {edge.target_key} not in graph"
            )

        edge_key = edge.canonical_key()

        # Check if this exact edge already exists in the multigraph
        if self._graph.has_edge(edge.source_key, edge.target_key, key=edge_key):
            existing: Edge = self._graph[edge.source_key][edge.target_key][edge_key]["data"]
            existing.merge_into(edge)
            return existing

        self._graph.add_edge(
            edge.source_key,
            edge.target_key,
            key=edge_key,
            data=edge,
        )
        return edge

    # ---- lookups -------------------------------------------------------------

    def has_node(self, key: tuple[Any, ...]) -> bool:
        """True if a node with this canonical_key exists in the graph."""
        return self._graph.has_node(key)

    def get_node(self, key: tuple[Any, ...]) -> Node:
        """Return the Node object with this canonical_key.

        Raises KeyError if not present.
        """
        if not self._graph.has_node(key):
            raise KeyError(f"No node with key {key}")
        return self._graph.nodes[key]["data"]

    # ---- queries -------------------------------------------------------------

    def find_nodes(
        self,
        node_type: str | None = None,
        predicate: Callable[[Node], bool] | None = None,
    ) -> Iterator[Node]:
        """Iterate nodes, optionally filtered by type and/or arbitrary predicate.

        node_type: filter by canonical_key()[0] (e.g., 'Process', 'File').
        predicate: callable returning True to include the node.
        """
        for key, attrs in self._graph.nodes(data=True):
            node: Node = attrs["data"]
            if node_type is not None and key[0] != node_type:
                continue
            if predicate is not None and not predicate(node):
                continue
            yield node

    def outgoing_edges(
        self,
        source_key: tuple[Any, ...],
        edge_type: str | None = None,
    ) -> Iterator[Edge]:
        """Iterate edges leaving the given node, optionally filtered by type."""
        if not self._graph.has_node(source_key):
            raise KeyError(f"No node with key {source_key}")
        for _, _, edge_key, attrs in self._graph.out_edges(source_key, keys=True, data=True):
            edge: Edge = attrs["data"]
            if edge_type is not None and edge_key[2] != edge_type:
                continue
            yield edge

    def incoming_edges(
        self,
        target_key: tuple[Any, ...],
        edge_type: str | None = None,
    ) -> Iterator[Edge]:
        """Iterate edges arriving at the given node, optionally filtered by type."""
        if not self._graph.has_node(target_key):
            raise KeyError(f"No node with key {target_key}")
        for _, _, edge_key, attrs in self._graph.in_edges(target_key, keys=True, data=True):
            edge: Edge = attrs["data"]
            if edge_type is not None and edge_key[2] != edge_type:
                continue
            yield edge

    # ---- sanity --------------------------------------------------------------

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def __repr__(self) -> str:
        return f"EvidenceGraph(nodes={self.node_count()}, edges={self.edge_count()})"
