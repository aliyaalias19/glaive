"""Text embedders and rerankers for evidence search.

Local first: nothing here is needed for keyword search, and the local
options keep every byte of evidence on the machine.

    GLAIVE_EMBED=fastembed     local ONNX model, no GPU (pip install "glaive[rag]"),
                               default sentence-transformers/paraphrase-multilingual-
                               MiniLM-L12-v2 (220 MB, 50+ languages incl. Chinese);
                               others via GLAIVE_EMBED_MODEL (e.g. BAAI/bge-small-en-v1.5)
    GLAIVE_EMBED=ollama        local Ollama server, default bge-m3 (ollama pull bge-m3)
    GLAIVE_EMBED=openai        text-embedding-3-small        (OPENAI_API_KEY)
    GLAIVE_EMBED=siliconflow   BAAI/bge-m3                   (SILICONFLOW_API_KEY)
    GLAIVE_EMBED=qwen          text-embedding-v4             (DASHSCOPE_API_KEY)
    GLAIVE_EMBED=jina          jina-embeddings-v3            (JINA_API_KEY)
    GLAIVE_EMBED=gemini        gemini-embedding-001          (GEMINI_API_KEY)
    GLAIVE_EMBED=custom        any OpenAI-compatible /embeddings server
                               (GLAIVE_EMBED_BASE_URL, GLAIVE_EMBED_MODEL)

    GLAIVE_RERANK=fastembed    local cross-encoder, default
                               jinaai/jina-reranker-v2-base-multilingual (1.1 GB;
                               licence CC BY-NC 4.0: non-commercial use only).
                               On the demo it helps; smaller rerankers made results
                               worse (see ACCURACY_REPORT.md), so reranking is off
                               unless you set this.
    GLAIVE_RERANK=siliconflow  BAAI/bge-reranker-v2-m3
    GLAIVE_RERANK=jina         jina-reranker-v2-base-multilingual
    GLAIVE_RERANK=custom       any Cohere/Jina-style /rerank server (GLAIVE_RERANK_BASE_URL)

Text sent to a cloud embedder or reranker is pseudonymised first, like model
calls (see glaive.security.privacy); GLAIVE_PRIVACY=local-only refuses them.
Default model names were checked in October 2026; providers rename models,
so override them if one stops working.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from glaive.security.privacy import Pseudonymizer, is_local_url, privacy_mode


class RetrievalConfigError(ValueError):
    """An embedder or reranker is misconfigured."""


class Embedder(Protocol):
    name: str
    local: bool

    def embed(self, texts: Sequence[str], kind: str = "document") -> list[list[float]]: ...


class Reranker(Protocol):
    name: str
    local: bool

    def rerank(self, query: str, documents: Sequence[str]) -> list[float]: ...


@dataclass(frozen=True)
class _Api:
    key_env: str | None
    base_url: str
    embed_model: str | None
    rerank_model: str | None = None


_APIS: dict[str, _Api] = {
    "ollama": _Api(None, "http://localhost:11434/v1", "bge-m3"),
    "openai": _Api("OPENAI_API_KEY", "https://api.openai.com/v1", "text-embedding-3-small"),
    "siliconflow": _Api("SILICONFLOW_API_KEY", "https://api.siliconflow.cn/v1", "BAAI/bge-m3",
                        "BAAI/bge-reranker-v2-m3"),
    "qwen": _Api("DASHSCOPE_API_KEY", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
                 "text-embedding-v4"),
    "jina": _Api("JINA_API_KEY", "https://api.jina.ai/v1", "jina-embeddings-v3",
                 "jina-reranker-v2-base-multilingual"),
    "gemini": _Api("GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai",
                   "gemini-embedding-001"),
    "custom": _Api("GLAIVE_EMBED_API_KEY", "", None),
}


class FastEmbedEmbedder:
    """Local ONNX embedding model (fastembed); downloads the model once."""

    local = True

    def __init__(self,
                 model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
                 ) -> None:
        try:
            from fastembed import TextEmbedding
        except ImportError as e:
            raise RetrievalConfigError(
                'Local embeddings need fastembed: pip install "glaive[rag]"') from e
        self.model_name = model
        self.name = f"fastembed:{model}"
        self._model = TextEmbedding(model_name=model)

    def embed(self, texts: Sequence[str], kind: str = "document") -> list[list[float]]:
        fn = self._model.query_embed if kind == "query" else self._model.embed
        return [list(map(float, v)) for v in fn(list(texts))]


class OpenAICompatEmbedder:
    """POST {base}/embeddings, as OpenAI, Ollama, SiliconFlow, DashScope, Jina
    and Gemini all accept."""

    def __init__(self, provider: str, base_url: str, model: str, api_key: str | None = None,
                 client: httpx.Client | None = None, privacy: Pseudonymizer | None = None,
                 batch: int = 64) -> None:
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=httpx.Timeout(120.0, connect=15.0))
        self.local = provider == "ollama" or is_local_url(self.base_url)
        self.privacy = None if self.local else privacy
        self.batch = batch
        self.name = f"{provider}:{model}"

    def embed(self, texts: Sequence[str], kind: str = "document") -> list[list[float]]:
        out: list[list[float]] = []
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        for i in range(0, len(texts), self.batch):
            chunk = list(texts[i:i + self.batch])
            if self.privacy is not None:
                for t in chunk:
                    self.privacy.learn_text(t)
                chunk = [self.privacy.mask(t) or "" for t in chunk]
            resp = self.client.post(f"{self.base_url}/embeddings", headers=headers,
                                    json={"model": self.model, "input": chunk})
            if resp.status_code >= 400:
                raise RetrievalConfigError(
                    f"{self.name} embeddings failed: HTTP {resp.status_code} {resp.text[:200]}")
            data = sorted(resp.json()["data"], key=lambda d: d.get("index", 0))
            out.extend([float(x) for x in d["embedding"]] for d in data)
        return out


class FastEmbedReranker:
    local = True

    def __init__(self, model: str = "jinaai/jina-reranker-v2-base-multilingual") -> None:
        try:
            from fastembed.rerank.cross_encoder import TextCrossEncoder
        except ImportError as e:
            raise RetrievalConfigError(
                'Local reranking needs fastembed: pip install "glaive[rag]"') from e
        self.name = f"fastembed:{model}"
        self._model = TextCrossEncoder(model_name=model)

    def rerank(self, query: str, documents: Sequence[str]) -> list[float]:
        return [float(s) for s in self._model.rerank(query, list(documents))]


class ApiReranker:
    """POST {base}/rerank (Cohere / Jina / SiliconFlow format)."""

    def __init__(self, provider: str, base_url: str, model: str, api_key: str | None = None,
                 client: httpx.Client | None = None,
                 privacy: Pseudonymizer | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0))
        self.local = is_local_url(self.base_url)
        self.privacy = None if self.local else privacy
        self.name = f"{provider}:{model}"

    def rerank(self, query: str, documents: Sequence[str]) -> list[float]:
        docs = list(documents)
        if self.privacy is not None:
            for t in (query, *docs):
                self.privacy.learn_text(t)
            query = self.privacy.mask(query) or ""
            docs = [self.privacy.mask(d) or "" for d in docs]
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        resp = self.client.post(f"{self.base_url}/rerank", headers=headers, json={
            "model": self.model, "query": query, "documents": docs, "top_n": len(docs),
            "return_documents": False})
        if resp.status_code >= 400:
            raise RetrievalConfigError(
                f"{self.name} rerank failed: HTTP {resp.status_code} {resp.text[:200]}")
        scores = [0.0] * len(docs)
        for r in resp.json().get("results", []):
            scores[int(r["index"])] = float(r.get("relevance_score", r.get("score", 0.0)))
        return scores


def _api_settings(kind: str, provider: str, env: Mapping[str, str]) -> tuple[str, str, str | None]:
    api = _APIS.get(provider)
    if api is None:
        raise RetrievalConfigError(f"Unknown {kind} provider {provider!r}; choose from "
                                   f"fastembed, {', '.join(sorted(_APIS))}.")
    up = kind.upper()
    base = env.get(f"GLAIVE_{up}_BASE_URL") or api.base_url
    default = api.embed_model if kind == "embed" else api.rerank_model
    model = env.get(f"GLAIVE_{up}_MODEL") or default
    if not base or not model:
        raise RetrievalConfigError(f"{provider} {kind}: set GLAIVE_{up}_BASE_URL and "
                                   f"GLAIVE_{up}_MODEL.")
    key = env.get(api.key_env) if api.key_env else None
    key = env.get(f"GLAIVE_{up}_API_KEY") or key
    if api.key_env and provider != "custom" and not key:
        raise RetrievalConfigError(f"{provider} {kind} needs {api.key_env}.")
    return base, model, key


def _check_privacy(local: bool, what: str, env: Mapping[str, str]) -> Pseudonymizer | None:
    mode = privacy_mode(env)
    if not local and mode == "local-only":
        raise RetrievalConfigError(f"GLAIVE_PRIVACY=local-only: {what} would send evidence to "
                                   "a cloud service. Use fastembed or ollama.")
    return Pseudonymizer() if mode == "pseudonymize" and not local else None


def embedder_from_env(env: Mapping[str, str] | None = None,
                      client: httpx.Client | None = None) -> Embedder | None:
    """The embedder chosen with GLAIVE_EMBED, or None (keyword search only)."""
    env = os.environ if env is None else env
    provider = (env.get("GLAIVE_EMBED") or "").strip().lower()
    if not provider or provider == "none":
        return None
    if provider == "fastembed":
        return FastEmbedEmbedder(env.get("GLAIVE_EMBED_MODEL")
                                 or "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
    base, model, key = _api_settings("embed", provider, env)
    local = provider == "ollama" or is_local_url(base)
    privacy = _check_privacy(local, "the embedder", env)
    return OpenAICompatEmbedder(provider, base, model, key, client=client, privacy=privacy)


def reranker_from_env(env: Mapping[str, str] | None = None,
                      client: httpx.Client | None = None) -> Reranker | None:
    env = os.environ if env is None else env
    provider = (env.get("GLAIVE_RERANK") or "").strip().lower()
    if not provider or provider == "none":
        return None
    if provider == "fastembed":
        return FastEmbedReranker(env.get("GLAIVE_RERANK_MODEL")
                                 or "jinaai/jina-reranker-v2-base-multilingual")
    base, model, key = _api_settings("rerank", provider, env)
    privacy = _check_privacy(is_local_url(base), "the reranker", env)
    return ApiReranker(provider, base, model, key, client=client, privacy=privacy)


def describe(obj: Any) -> str | None:
    return getattr(obj, "name", None) if obj is not None else None
