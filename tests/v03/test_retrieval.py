"""Evidence search: documents, BM25, vectors, fusion, reranking, tools."""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

import httpx
import pytest

from glaive.demo.case import ANSWER_KEY, C2, WS
from glaive.mcp_server.session import GlaiveSession
from glaive.retrieval.embeddings import (
    ApiReranker,
    OpenAICompatEmbedder,
    RetrievalConfigError,
    embedder_from_env,
    reranker_from_env,
)
from glaive.retrieval.evaluate import DEMO_QUESTIONS, evaluate, to_markdown
from glaive.retrieval.index import EvidenceIndex, fts_query, index_for, node_document
from glaive.security.privacy import Pseudonymizer


class HashEmbedder:
    """Deterministic bag-of-words vectors: tests the vector path without a model."""

    name = "test:hash"
    local = True
    dim = 64

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def embed(self, texts, kind="document"):  # noqa: ANN001, ANN201
        self.calls.append((kind, len(texts)))
        out = []
        for t in texts:
            v = [0.0] * self.dim
            for w in re.findall(r"\w+", t.lower()):
                v[int(hashlib.md5(w.encode()).hexdigest(), 16) % self.dim] += 1.0
            out.append(v)
        return out


class ReverseReranker:
    name = "test:reverse"
    local = True

    def rerank(self, query, documents):  # noqa: ANN001, ANN201
        return [float(i) for i in range(len(documents))]  # last one becomes best


@pytest.fixture
def idx(demo_session: GlaiveSession, tmp_path: Path) -> EvidenceIndex:
    i = EvidenceIndex(tmp_path / "s.sqlite")
    i.build(demo_session.graph)
    return i


def test_fts_query_is_safe() -> None:
    assert fts_query('the "evil" OR* (x) AND y NEAR(') == '"evil" OR "near"'
    assert fts_query("what is the") is None
    q = fts_query("comsvcs.dll MiniDump 712")
    assert q is not None and '"comsvcs"' in q and '"712"' in q


def test_documents_include_neighbours_and_tactics(demo_session: GlaiveSession) -> None:
    g = demo_session.graph
    docs = [node_document(g, n) for n in g.find_nodes("Process")
            if n.name.lower() == "powershell.exe"]
    # the parent process is described in the child's document (GraphRAG)
    assert any("Spawned <- Process WINWORD.EXE" in d for d in docs), docs[0]
    alert = next(a for a in g.find_nodes("Alert") if "Credential Dumping" in a.title)
    assert "ATT&CK tactics: Credential Access" in node_document(g, alert)


def test_keyword_search_and_filters(idx: EvidenceIndex) -> None:
    hits = idx.search("comsvcs MiniDump lsass", 5, mode="bm25")
    assert hits and any("Credential Dumping" in h.label for h in hits[:2])
    assert all(h.ranks.keys() == {"bm25"} for h in hits)
    only = idx.search("powershell", 10, mode="bm25", node_type="Process")
    assert only and {h.node_type for h in only} == {"Process"}
    hosted = idx.search("powershell", 10, mode="bm25", host=WS.lower())
    hosts = {r[0] for h in hosted for r in idx._db.execute(
        "SELECT host FROM docs WHERE key = ?", (json.dumps(h.key, default=str),))}
    assert hosted and hosts == {WS}
    assert idx.search("the and of", 5) == []
    with pytest.raises(ValueError):
        idx.search("x", mode="fuzzy")


def test_hits_are_citable_graph_nodes(idx: EvidenceIndex, demo_session: GlaiveSession) -> None:
    from glaive.mcp_server import tools

    hit = idx.search("vssadmin delete shadows", 1, mode="bm25")[0]
    key = tools.resolve_key(demo_session, hit.key)
    assert demo_session.graph.has_node(key)
    d = hit.to_dict(max_text=50)
    assert d["canonical_key"] == hit.key and d["text"].endswith("...")


def test_hybrid_fuses_both_lists_and_reranks(demo_session: GlaiveSession, tmp_path: Path) -> None:
    emb = HashEmbedder()
    i = EvidenceIndex(tmp_path / "h.sqlite", emb, ReverseReranker())
    built = i.build(demo_session.graph)
    assert built["embedded"] == built["documents"] > 100
    assert i.info()["vectors"] == built["documents"] and i.info()["embedder"] == "test:hash"
    dense = i.search("shadow copies deleted", 5, mode="dense", rerank=False)
    assert dense and all(set(h.ranks) == {"dense"} for h in dense)
    hybrid = i.search("shadow copies deleted", 5, rerank=False)
    assert any({"bm25", "dense"} <= set(h.ranks) for h in hybrid)
    reranked = i.search("shadow copies deleted", 5)
    assert [h.ranks["rerank"] for h in reranked] == [1, 2, 3, 4, 5]
    assert ("query", 1) in emb.calls


def test_embedding_budget_prefers_alerts(demo_session: GlaiveSession, tmp_path: Path) -> None:
    i = EvidenceIndex(tmp_path / "b.sqlite", HashEmbedder(), max_embed_docs=10)
    assert i.build(demo_session.graph)["embedded"] == 10
    types = {r[0] for r in i._db.execute(
        "SELECT d.node_type FROM vecs v JOIN docs d ON d.id = v.id")}
    assert types == {"Alert"}


def test_index_is_rebuilt_only_when_the_graph_changes(demo_session: GlaiveSession) -> None:
    from glaive.graph.nodes import Host

    first = index_for(demo_session)
    assert first.ensure(demo_session.graph) is None  # already current
    demo_session.graph.add_node(Host(evidence_hash="b" * 64, derivation="test",
                                     hostname="NEW-HOST"))
    again = index_for(demo_session)
    assert again is first and again.search("NEW-HOST", 1, mode="bm25")[0].label == "NEW-HOST"
    assert any(e["action"] == "index_built" for e in demo_session.audit_log)


def test_release_closes_open_indexes(demo_session: GlaiveSession) -> None:
    from glaive.retrieval.index import _OPEN, release_indexes

    index_for(demo_session)
    root = str(demo_session.analysis_dir.resolve())
    assert any(k.startswith(root) for k in _OPEN)
    release_indexes(demo_session.analysis_dir)
    assert not any(k.startswith(root) for k in _OPEN)


def _embed_api(captured: list[dict]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.append({"url": str(request.url), "body": body,
                         "auth": request.headers.get("authorization")})
        if request.url.path.endswith("/rerank"):
            n = len(body["documents"])
            return httpx.Response(200, json={"results": [
                {"index": i, "relevance_score": 1 - i / n} for i in reversed(range(n))]})
        return httpx.Response(200, json={"data": [
            {"index": i, "embedding": [1.0, float(len(t))]} for i, t in enumerate(body["input"])]})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_api_embedder_batches_and_masks_for_the_cloud() -> None:
    seen: list[dict] = []
    p = Pseudonymizer()
    p.add("host", WS)
    e = OpenAICompatEmbedder("siliconflow", "https://api.siliconflow.cn/v1", "BAAI/bge-m3", "k",
                             client=_embed_api(seen), privacy=p, batch=2)
    vecs = e.embed([f"logon on {WS}", "b", "c"])
    assert len(vecs) == 3 and len(seen) == 2 and seen[0]["auth"] == "Bearer k"
    assert WS not in json.dumps(seen) and "HOST_1" in seen[0]["body"]["input"][0]
    local = OpenAICompatEmbedder("ollama", "http://localhost:11434/v1", "bge-m3",
                                 client=_embed_api(seen), privacy=p)
    assert local.local and local.privacy is None
    local.embed([WS])
    assert WS in seen[-1]["body"]["input"][0]


def test_api_reranker_and_errors() -> None:
    seen: list[dict] = []
    r = ApiReranker("jina", "https://api.jina.ai/v1", "jina-reranker-v2-base-multilingual", "k",
                    client=_embed_api(seen))
    scores = r.rerank("q", ["a", "b", "c"])
    assert scores == [1.0, pytest.approx(2 / 3), pytest.approx(1 / 3)]
    assert seen[0]["body"]["top_n"] == 3

    def fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="bad key")

    bad = OpenAICompatEmbedder("openai", "https://api.openai.com/v1", "m", "k",
                               client=httpx.Client(transport=httpx.MockTransport(fail)))
    with pytest.raises(RetrievalConfigError, match="HTTP 401"):
        bad.embed(["x"])


def test_configuration_from_environment() -> None:
    assert embedder_from_env({}) is None and reranker_from_env({"GLAIVE_RERANK": "none"}) is None
    e = embedder_from_env({"GLAIVE_EMBED": "ollama"})
    assert e is not None and e.local and e.name == "ollama:bge-m3"
    e = embedder_from_env({"GLAIVE_EMBED": "qwen", "DASHSCOPE_API_KEY": "k",
                           "GLAIVE_EMBED_MODEL": "text-embedding-v3"})
    assert e is not None and not e.local and e.name == "qwen:text-embedding-v3"
    assert e.privacy is not None  # cloud: pseudonymised by default
    r = reranker_from_env({"GLAIVE_RERANK": "siliconflow", "SILICONFLOW_API_KEY": "k"})
    assert r is not None and r.name == "siliconflow:BAAI/bge-reranker-v2-m3"
    with pytest.raises(RetrievalConfigError, match="needs SILICONFLOW_API_KEY"):
        embedder_from_env({"GLAIVE_EMBED": "siliconflow"})
    with pytest.raises(RetrievalConfigError, match="local-only"):
        embedder_from_env({"GLAIVE_EMBED": "openai", "OPENAI_API_KEY": "k",
                           "GLAIVE_PRIVACY": "local-only"})
    with pytest.raises(RetrievalConfigError, match="Unknown embed provider"):
        embedder_from_env({"GLAIVE_EMBED": "nope"})
    with pytest.raises(RetrievalConfigError, match="GLAIVE_EMBED_BASE_URL"):
        embedder_from_env({"GLAIVE_EMBED": "custom"})


def test_recall_at_k_on_the_demo(idx: EvidenceIndex) -> None:
    r = evaluate(idx, ANSWER_KEY, mode="bm25")
    assert r["questions"] == len(DEMO_QUESTIONS)
    assert 0.4 <= r["recall@10"] <= 1.0 and r["recall@1"] <= r["recall@10"]
    assert 0.0 <= r["mrr"] <= 1.0 and math.isfinite(r["mrr"])
    assert "| bm25 |" in to_markdown([r])


def test_agent_and_mcp_search_tool(demo_session: GlaiveSession) -> None:
    from glaive.agents.toolbox import AgentToolbox
    from glaive.llm import ToolCall

    tb = AgentToolbox(demo_session)
    assert "search_evidence" in [s.name for s in tb.specs()]
    out = tb.execute(ToolCall("1", "search_evidence", {"query": f"connection to {C2}"}))
    payload = json.loads("\n".join(out.splitlines()[1:-1]))
    assert payload["returned"] > 0
    top = payload["results"][0]
    node = json.loads("\n".join(tb.execute(ToolCall(
        "2", "get_node", {"canonical_key": top["canonical_key"]})).splitlines()[1:-1]))
    assert "node" in node  # a search result can be opened and cited


async def test_mcp_lists_search_evidence(demo_session: GlaiveSession) -> None:
    from glaive.mcp_server.server import build_server

    names = [t.name for t in await build_server(demo_session).list_tools()]
    assert "search_evidence" in names


def test_cli_search_and_retrieval_bench(demo_session: GlaiveSession) -> None:
    from typer.testing import CliRunner

    from glaive.cli import app

    demo_session.save()
    r = CliRunner().invoke(app, ["search", str(demo_session.analysis_dir), "shadow copies",
                                 "--mode", "bm25"])
    assert r.exit_code == 0, r.output
    assert "Volume Shadow Copies Deleted" in r.output and "keyword search only" in r.output
    r = CliRunner().invoke(app, ["bench", "retrieval"])
    assert r.exit_code == 0, r.output
    assert "| bm25 |" in r.output
