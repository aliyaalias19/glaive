"""Evidence search (GraphRAG): hybrid keyword + vector retrieval over the graph."""
from __future__ import annotations

import os
import threading
from typing import Any

from glaive.retrieval.embeddings import (
    RetrievalConfigError,
    embedder_from_env,
    reranker_from_env,
)
from glaive.retrieval.index import EvidenceIndex, RetrievalError, SearchHit, index_for

_ENV_KEYS = ("GLAIVE_EMBED", "GLAIVE_EMBED_MODEL", "GLAIVE_EMBED_BASE_URL", "GLAIVE_RERANK",
             "GLAIVE_RERANK_MODEL", "GLAIVE_RERANK_BASE_URL", "GLAIVE_PRIVACY")
_CACHE: dict[tuple[str, ...], tuple[Any, Any]] = {}
_LOCK = threading.Lock()


def configured_models() -> tuple[Any, Any]:
    """(embedder, reranker) from the environment, loaded once per configuration
    (local models take a few seconds to load)."""
    key = tuple(os.environ.get(k, "") for k in _ENV_KEYS)
    with _LOCK:
        if key not in _CACHE:
            _CACHE[key] = (embedder_from_env(), reranker_from_env())
        return _CACHE[key]


def search_session(session: Any, query: str, k: int = 10, **kw: Any) -> list[SearchHit]:
    """Search a case with the embedder/reranker configured in the environment."""
    embedder, reranker = configured_models()
    return index_for(session, embedder, reranker).search(query, k, **kw)


__all__ = ["EvidenceIndex", "RetrievalConfigError", "RetrievalError", "SearchHit",
           "configured_models", "embedder_from_env", "index_for", "reranker_from_env",
           "search_session"]
