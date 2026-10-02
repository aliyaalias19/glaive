"""GLAIVE evidence graph wrapper - the typed graph that holds nodes and edges.

Backed by networkx.MultiDiGraph. Provides:
  - Type-aware add/merge semantics (auto-merge on canonical_key collision)
  - Pythonic query API (returns Node/Edge objects, not raw NetworkX tuples)
  - Strict endpoint checking (raises if edge points to a missing node)
  - Traversal helpers for agents (neighbours, paths, timeline)
  - Lossless JSON (de)serialization, used by the .glaive case file

Design decisions:
  W1 - Node ID = node.canonical_key() tuple
  W2 - add_node auto-merges if key already exists
  W3 - Edge stored with edge.canonical_key() as the multigraph edge key
  W4 - Missing endpoint nodes raise KeyError (caller adds first)
  W5 - Query API returns objects, optionally filtered by type / predicate
  W6 - All mutations hold a re-entrant lock (web app + agents share a graph)
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any

import networkx as nx

from glaive.graph.base import Edge, Node

# ---- key codec ----------------------------------------------------------------
# Canonical keys are tuples that may contain datetimes and None. JSON has
# neither tuples nor datetimes, so keys are tagged when saved to disk.


def encode_key(key: Any) -> Any:
    """Encode a canonical key (tuples, datetimes, None, scalars) as tagged JSON."""
    if isinstance(key, tuple):
        return {"$t": [encode_key(k) for k in key]}
    if isinstance(key, datetime):
        return {"$dt": key.isoformat()}
    return key


def decode_key(obj: Any) -> Any:
    """Inverse of encode_key."""
    if isinstance(obj, dict):
        if "$t" in obj:
            return tuple(decode_key(k) for k in obj["$t"])
        if "$dt" in obj:
            return datetime.fromisoformat(obj["$dt"])
    if isinstance(obj, list):
        return tuple(decode_key(k) for k in obj)
    return obj


_TIME_FIELDS = ("detection_time", "start_time", "first_seen", "btime",
                "last_write_time", "last_run_time")


class EvidenceGraph:
    """Typed evidence graph backed by networkx.MultiDiGraph.

    Use add_node / add_edge for ingestion. Use find_nodes,
    outgoing_edges, incoming_edges for queries.

    Reference: docs/EVIDENCE_GRAPH_SCHEMA.md.
    """

    def __init__(self) -> None:
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._lock = threading.RLock()
        self.version = 0  # bumped on every mutation

    # ---- ingestion -----------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        """Add a node to the graph, or merge into an existing one if the
        canonical_key already exists.

        Returns the resulting node (either the newly-added one, or the
        existing one after merging).

        W2: auto-merge semantics.
        """
        key = node.canonical_key()
        with self._lock:
            self.version += 1
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
        with self._lock:
            if not self._graph.has_node(edge.source_key):
                raise KeyError(f"Cannot add edge: source node {edge.source_key} not in graph")
            if not self._graph.has_node(edge.target_key):
                raise KeyError(f"Cannot add edge: target node {edge.target_key} not in graph")

            edge_key = edge.canonical_key()
            self.version += 1

            if self._graph.has_edge(edge.source_key, edge.target_key, key=edge_key):
                existing: Edge = self._graph[edge.source_key][edge.target_key][edge_key]["data"]
                existing.merge_into(edge)
                return existing

            self._graph.add_edge(edge.source_key, edge.target_key, key=edge_key, data=edge)
            return edge

    def has_edge_key(self, edge: Edge) -> bool:
        """True if an edge with this edge's canonical key already exists."""
        return self._graph.has_edge(edge.source_key, edge.target_key, key=edge.canonical_key())

    # ---- lookups -------------------------------------------------------------

    def has_node(self, key: tuple[Any, ...]) -> bool:
        """True if a node with this canonical_key exists in the graph."""
        try:
            return self._graph.has_node(key)
        except TypeError:  # unhashable key from untrusted input
            return False

    def get_node(self, key: tuple[Any, ...]) -> Node:
        """Return the Node object with this canonical_key.

        Raises KeyError if not present.
        """
        if not self.has_node(key):
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
        for key, attrs in list(self._graph.nodes(data=True)):
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
            if edge_type is not None and edge_key[2] != edge_type:
                continue
            yield attrs["data"]

    def incoming_edges(
        self,
        target_key: tuple[Any, ...],
        edge_type: str | None = None,
    ) -> Iterator[Edge]:
        """Iterate edges arriving at the given node, optionally filtered by type."""
        if not self._graph.has_node(target_key):
            raise KeyError(f"No node with key {target_key}")
        for _, _, edge_key, attrs in self._graph.in_edges(target_key, keys=True, data=True):
            if edge_type is not None and edge_key[2] != edge_type:
                continue
            yield attrs["data"]

    def all_edges(self, edge_type: str | None = None) -> Iterator[Edge]:
        """Iterate every edge, optionally filtered by type."""
        for _, _, edge_key, attrs in list(self._graph.edges(keys=True, data=True)):
            if edge_type is not None and edge_key[2] != edge_type:
                continue
            yield attrs["data"]

    # ---- neighbourhood (used by the grounding check and agents) ----------------

    def neighbors(self, key: tuple[Any, ...], depth: int = 1, max_nodes: int = 200) -> set[tuple]:
        """The node plus every node within `depth` hops, ignoring edge direction."""
        if not self._graph.has_node(key):
            raise KeyError(f"No node with key {key}")
        seen = {key}
        frontier = [key]
        for _ in range(max(0, depth)):
            nxt = []
            for k in frontier:
                for n in list(self._graph.successors(k)) + list(self._graph.predecessors(k)):
                    if n not in seen:
                        seen.add(n)
                        nxt.append(n)
                        if len(seen) >= max_nodes:
                            return seen
            frontier = nxt
        return seen

    def subgraph(self, keys: set[tuple]) -> tuple[list[Node], list[Edge]]:
        """The given nodes and the edges between them."""
        sub = self._graph.subgraph(keys)
        nodes = [a["data"] for _, a in sub.nodes(data=True)]
        edges = [a["data"] for _, _, a in sub.edges(data=True)]
        return nodes, edges

    def shortest_path(self, a: tuple, b: tuple) -> list[tuple] | None:
        """Shortest path between two nodes ignoring direction, or None."""
        try:
            return nx.shortest_path(self._graph.to_undirected(as_view=True), a, b)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def timeline(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Chronological list of time-stamped nodes and edges."""
        events: list[tuple[datetime, dict[str, Any]]] = []
        for key, attrs in list(self._graph.nodes(data=True)):
            node = attrs["data"]
            for f in _TIME_FIELDS:
                ts = getattr(node, f, None)
                if isinstance(ts, datetime):
                    events.append((ts, {"kind": "node", "node_type": key[0], "field": f,
                                        "key": key, "node": node}))
                    break
        for edge in self.all_edges():
            if edge.timestamp is not None:
                events.append((edge.timestamp, {"kind": "edge", "edge_type": edge.edge_type,
                                                "source": edge.source_key,
                                                "target": edge.target_key, "edge": edge}))
        if start is not None:
            events = [e for e in events if e[0] >= start]
        if end is not None:
            events = [e for e in events if e[0] <= end]
        events.sort(key=lambda e: e[0])
        return [{"time": t, **e} for t, e in events[:limit]]

    # ---- serialization ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Lossless JSON-safe snapshot of every node and edge."""
        with self._lock:
            nodes = [{"type": n.node_type, "data": n.model_dump(mode="json")}
                     for n in self.find_nodes()]
            edges = []
            for e in self.all_edges():
                d = e.model_dump(mode="json", exclude={"source_key", "target_key"})
                edges.append({"type": e.edge_type, "source": encode_key(e.source_key),
                              "target": encode_key(e.target_key), "data": d})
            return {"schema": 1, "nodes": nodes, "edges": edges}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceGraph:
        """Rebuild a graph saved with to_dict()."""
        from glaive.graph.edges import edge_registry
        from glaive.graph.nodes import node_registry

        g = cls()
        nreg, ereg = node_registry(), edge_registry()
        for item in data.get("nodes", []):
            g.add_node(nreg[item["type"]].model_validate(item["data"]))
        for item in data.get("edges", []):
            payload = dict(item["data"])
            payload["source_key"] = decode_key(item["source"])
            payload["target_key"] = decode_key(item["target"])
            g.add_edge(ereg[item["type"]].model_validate(payload))
        return g

    # ---- sanity --------------------------------------------------------------

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def type_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for key in self._graph.nodes:
            out[key[0]] = out.get(key[0], 0) + 1
        return dict(sorted(out.items()))

    def __repr__(self) -> str:
        return f"EvidenceGraph(nodes={self.node_count()}, edges={self.edge_count()})"
