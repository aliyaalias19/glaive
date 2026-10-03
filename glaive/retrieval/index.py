"""Evidence search: hybrid keyword + vector retrieval over the evidence graph.

Every graph node becomes one document: its type, its fields, and a short
description of the nodes it is connected to (its parent process, user, host,
network connections...). That neighbourhood is what makes this GraphRAG
rather than plain text search: "PowerShell started by Word" finds the
PowerShell node even though "Word" is only in its parent.

Ranking:
  1. BM25 keyword search (SQLite FTS5): exact names, paths, IPs, hashes.
  2. Dense vectors (optional, see glaive.retrieval.embeddings): meaning,
     other languages ("凭据窃取" finds credential dumping with a
     multilingual model).
  3. Reciprocal Rank Fusion (k=60) merges the two lists.
  4. An optional cross-encoder reranker reorders the top results.

The index lives next to the case file (<case>/search.sqlite) and is rebuilt
automatically when the graph changes. Hits are graph nodes, so every answer
built from them can be cited and checked by the verification gate.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from glaive.detection.attack import tactic_name
from glaive.mcp_server import tools as core
from glaive.retrieval.embeddings import Embedder, Reranker

INDEX_FILENAME = "search.sqlite"
SCHEMA_VERSION = "1"
RRF_K = 60
MAX_DOC_CHARS = 2000
MAX_NEIGHBOURS = 12
# Embedding is the slow, possibly paid step: the most telling node types go first.
EMBED_PRIORITY = ("Alert", "AntivirusDetection", "ScriptBlock", "Service", "ScheduledTask",
                  "RegistryKey", "NetworkEndpoint", "Process", "File", "User", "Host")
_SKIP_FIELDS = {"canonical_key", "evidence_hash", "node_type", "derivation", "source_tool",
                "observed_by", "confirmed_by"}
_LABEL_FIELDS = ("title", "name", "threat_name", "event_description", "hostname", "username",
                 "service_name", "task_path", "value_name", "remote_addr", "full_path", "domain")
_STOP = frozenset("""a an and any are as at be by did do does for from has have how in into is it
its of on or so that the their there this to was were what when where which who why with
attacker case evidence show find any all""".split())
# Same characters as the index tokenizer, so "WS-FIN-07" is one word in both.
_WORD = re.compile(r"[\w$-]+", re.UNICODE)


class RetrievalError(RuntimeError):
    """The search index could not be built or queried."""


def node_label(node: Any) -> str:
    for f in _LABEL_FIELDS:
        v = getattr(node, f, None)
        if v:
            return str(v)[:120]
    return node.node_type


def node_document(graph: Any, node: Any) -> str:
    """Searchable text for one node: what it is, its fields, its neighbours."""
    s = core._node_summary(node)
    lines = [f"{node.node_type}: {node_label(node)}"]
    tactics = getattr(node, "mitre_tactics", None)
    if tactics:  # words an analyst uses: "credential access", "persistence"...
        lines.append("ATT&CK tactics: " + ", ".join(tactic_name(t) for t in tactics))
    for k, v in s.items():
        if k in _SKIP_FIELDS:
            continue
        if isinstance(v, (list, dict)):
            v = json.dumps(v, ensure_ascii=False)
        lines.append(f"{k}: {v}")
    key = node.canonical_key()
    related = []
    for e in list(graph.outgoing_edges(key))[:MAX_NEIGHBOURS]:
        other = graph.get_node(e.target_key)
        related.append(f"{e.edge_type} -> {other.node_type} {node_label(other)}")
    for e in list(graph.incoming_edges(key))[:MAX_NEIGHBOURS]:
        other = graph.get_node(e.source_key)
        related.append(f"{e.edge_type} <- {other.node_type} {node_label(other)}")
    if related:
        lines.append("related: " + "; ".join(related))
    return "\n".join(lines)[:MAX_DOC_CHARS]


def graph_fingerprint(graph: Any) -> str:
    """Cheap change detector: the graph only grows (ingestion adds nodes and
    edges; merges add sources to existing ones), so its size identifies it."""
    return f"{graph.node_count()}:{graph.edge_count()}"


def fts_query(text: str) -> str | None:
    """User text -> a safe FTS5 query: every meaningful word, OR-ed, quoted."""
    words = [w.strip("-").lower() for w in _WORD.findall(text)]
    words = [w for w in words if len(w) > 1 and w not in _STOP]
    if not words:
        return None
    seen: list[str] = []
    for w in words:
        if w not in seen:
            seen.append(w)
    return " OR ".join('"' + w.replace('"', '""') + '"' for w in seen[:40])


@dataclass
class SearchHit:
    key: list[Any]                 # canonical_key, JSON-safe (cite it as is)
    node_type: str
    label: str
    score: float
    text: str
    ranks: dict[str, int] = field(default_factory=dict)  # bm25 / dense / rerank

    def to_dict(self, max_text: int = 600) -> dict[str, Any]:
        return {"canonical_key": self.key, "node_type": self.node_type, "label": self.label,
                "score": round(self.score, 5), "ranks": self.ranks,
                "text": self.text[:max_text] + ("..." if len(self.text) > max_text else "")}


class EvidenceIndex:
    """One search index per case (thread-safe)."""

    def __init__(self, path: Path, embedder: Embedder | None = None,
                 reranker: Reranker | None = None, max_embed_docs: int = 20_000) -> None:
        self.path = Path(path)
        self.embedder = embedder
        self.reranker = reranker
        self.max_embed_docs = max_embed_docs
        self._lock = threading.RLock()
        self._matrix: Any = None
        self._matrix_ids: list[int] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        try:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS docs (id INTEGER PRIMARY KEY, key TEXT UNIQUE,
                    node_type TEXT, host TEXT, label TEXT, text TEXT);
                CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
                    text, content='docs', content_rowid='id',
                    tokenize="unicode61 remove_diacritics 2 tokenchars '-_$'");
                CREATE TABLE IF NOT EXISTS vecs (id INTEGER PRIMARY KEY, v BLOB);
            """)
        except sqlite3.OperationalError as e:
            self._db.close()
            raise RetrievalError(f"This Python's SQLite cannot build the search index: {e}") from e

    # ---- meta ----------------------------------------------------------------------

    def _meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def info(self) -> dict[str, Any]:
        return {"documents": self._db.execute("SELECT COUNT(*) FROM docs").fetchone()[0],
                "vectors": self._db.execute("SELECT COUNT(*) FROM vecs").fetchone()[0],
                "embedder": self._meta("embedder"), "fingerprint": self._meta("fingerprint"),
                "reranker": getattr(self.reranker, "name", None)}

    def is_current(self, graph: Any) -> bool:
        return self._meta("schema") == SCHEMA_VERSION and \
            self._meta("fingerprint") == graph_fingerprint(graph) and \
            self._meta("embedder") == (self.embedder.name if self.embedder else "")

    # ---- build -----------------------------------------------------------------------

    def build(self, graph: Any) -> dict[str, Any]:
        """(Re)index every node of the graph."""
        import numpy as np

        with self._lock, self._db:
            self._db.execute("DELETE FROM docs")
            self._db.execute("DELETE FROM vecs")
            self._db.execute("INSERT INTO fts(fts) VALUES('delete-all')")
            rows = []
            for i, n in enumerate(graph.find_nodes(), 1):
                host = getattr(n, "host_hostname", None) or getattr(n, "hostname", None)
                rows.append((i, json.dumps(core._json_safe(n.canonical_key()), default=str),
                             n.node_type, host, node_label(n), node_document(graph, n)))
            self._db.executemany("INSERT INTO docs VALUES(?,?,?,?,?,?)", rows)
            self._db.execute("INSERT INTO fts(fts) VALUES('rebuild')")
            embedded = 0
            if self.embedder is not None and rows:
                order = {t: i for i, t in enumerate(EMBED_PRIORITY)}
                chosen = sorted(rows, key=lambda r: (order.get(r[2], len(order)), r[0]))
                chosen = chosen[:self.max_embed_docs]
                vectors = self.embedder.embed([r[5] for r in chosen], kind="document")
                arr = np.asarray(vectors, dtype=np.float32)
                arr /= np.linalg.norm(arr, axis=1, keepdims=True) + 1e-12
                self._db.executemany("INSERT INTO vecs VALUES(?, ?)",
                                     [(r[0], arr[j].tobytes()) for j, r in enumerate(chosen)])
                embedded = len(chosen)
            for k, v in (("schema", SCHEMA_VERSION), ("fingerprint", graph_fingerprint(graph)),
                         ("embedder", self.embedder.name if self.embedder else "")):
                self._db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v))
            self._matrix = None
        return {"documents": len(rows), "embedded": embedded}

    def ensure(self, graph: Any) -> dict[str, Any] | None:
        """Build if missing or stale; None when already current."""
        with self._lock:
            return None if self.is_current(graph) else self.build(graph)

    # ---- search ----------------------------------------------------------------------

    def _bm25(self, query: str, limit: int, where: str, params: list[Any]) -> list[int]:
        q = fts_query(query)
        if q is None:
            return []
        sql = ("SELECT d.id FROM fts JOIN docs d ON d.id = fts.rowid WHERE fts MATCH ?"
               f"{where} ORDER BY bm25(fts) LIMIT ?")
        return [r[0] for r in self._db.execute(sql, [q, *params, limit])]

    def _dense(self, query: str, limit: int, allowed: set[int] | None) -> list[int]:
        import numpy as np

        if self.embedder is None:
            return []
        if self._matrix is None:
            rows = self._db.execute("SELECT id, v FROM vecs ORDER BY id").fetchall()
            if not rows:
                return []
            self._matrix_ids = [r[0] for r in rows]
            self._matrix = np.vstack([np.frombuffer(r[1], dtype=np.float32) for r in rows])
        q = np.asarray(self.embedder.embed([query], kind="query")[0], dtype=np.float32)
        q /= np.linalg.norm(q) + 1e-12
        scores = self._matrix @ q
        order = np.argsort(-scores)
        out = []
        for j in order:
            doc_id = self._matrix_ids[int(j)]
            if allowed is None or doc_id in allowed:
                out.append(doc_id)
                if len(out) >= limit:
                    break
        return out

    def search(self, query: str, k: int = 10, *, mode: str = "hybrid",
               node_type: str | None = None, host: str | None = None,
               rerank: bool = True, candidates: int = 50) -> list[SearchHit]:
        """Top-k nodes for a question. mode: hybrid, bm25 or dense."""
        if mode not in ("hybrid", "bm25", "dense"):
            raise ValueError("mode must be hybrid, bm25 or dense")
        where, params = "", []
        if node_type:
            where += " AND d.node_type = ?"
            params.append(node_type)
        if host:
            where += " AND lower(d.host) = lower(?)"
            params.append(host)
        with self._lock:
            lists: dict[str, list[int]] = {}
            if mode in ("hybrid", "bm25"):
                lists["bm25"] = self._bm25(query, candidates, where, params)
            if mode in ("hybrid", "dense") and self.embedder is not None:
                allowed = None
                if where:
                    allowed = {r[0] for r in self._db.execute(
                        f"SELECT id FROM docs d WHERE 1=1{where}", params)}
                lists["dense"] = self._dense(query, candidates, allowed)
            fused: dict[int, float] = {}
            ranks: dict[int, dict[str, int]] = {}
            for name, ids in lists.items():
                for rank, doc_id in enumerate(ids, 1):
                    fused[doc_id] = fused.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
                    ranks.setdefault(doc_id, {})[name] = rank
            ordered = sorted(fused, key=lambda d: -fused[d])
            if not ordered:
                return []
            top = ordered[:max(k, min(len(ordered), 20))]
            docs = {r[0]: r for r in self._db.execute(
                f"SELECT id, key, node_type, label, text FROM docs WHERE id IN "
                f"({','.join('?' * len(top))})", top)}
            hits = [SearchHit(json.loads(docs[d][1]), docs[d][2], docs[d][3], fused[d],
                              docs[d][4], ranks[d]) for d in top if d in docs]
        if rerank and self.reranker is not None and len(hits) > 1:
            scores = self.reranker.rerank(query, [h.text for h in hits])
            for h, s in zip(hits, scores, strict=True):
                h.score = s
            hits.sort(key=lambda h: -h.score)
            for i, h in enumerate(hits, 1):
                h.ranks["rerank"] = i
        return hits[:k]

    def close(self) -> None:
        self._db.close()


_OPEN: dict[str, EvidenceIndex] = {}
_OPEN_LOCK = threading.Lock()


def release_indexes(folder: Path) -> None:
    """Close the open indexes stored under a folder (Windows cannot delete
    open files)."""
    root = str(Path(folder).resolve())
    with _OPEN_LOCK:
        for key in [k for k in _OPEN if k.split("|", 1)[0].startswith(root)]:
            _OPEN.pop(key).close()


def index_for(session: Any, embedder: Embedder | None = None,
              reranker: Reranker | None = None) -> EvidenceIndex:
    """The (current) search index of a session, built on first use."""
    path = session.analysis_dir / INDEX_FILENAME
    key = f"{path.resolve()}|{getattr(embedder, 'name', '')}|{getattr(reranker, 'name', '')}"
    with _OPEN_LOCK:
        idx = _OPEN.get(key)
        if idx is None:
            idx = EvidenceIndex(path, embedder, reranker)
            _OPEN[key] = idx
    built = idx.ensure(session.graph)
    if built is not None and hasattr(session, "log"):
        session.log("search", "index_built", **built,
                    embedder=getattr(embedder, "name", None))
    return idx
