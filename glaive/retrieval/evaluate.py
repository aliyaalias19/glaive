"""How well does evidence search find the right nodes? recall@k and MRR.

The demo case comes with questions an analyst might type, written without the
words of the answer key or of the rule titles (a search that only matches
the exact rule title would score well on the titles and badly in real life).
A node is relevant to a question when its document contains every term of
the matching answer-key item.

    recall@k  share of questions with at least one relevant node in the top k
    MRR       mean of 1 / rank of the first relevant node (0 if none in the top 20)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from glaive.retrieval.index import EvidenceIndex

# (answer-key id, question). Chinese questions check cross-language search.
DEMO_QUESTIONS: list[tuple[str, str]] = [
    ("GT1", "Did opening a document start a command shell?"),
    ("GT2", "Was a script used to download something from the internet?"),
    ("GT3", "Was the antivirus switched off?"),
    ("GT4", "How does the malware survive a reboot?"),
    ("GT5", "Is any program beaconing to an external server?"),
    ("GT6", "Did someone look up who the domain administrators are?"),
    ("GT7", "Were passwords stolen from memory?"),
    ("GT8", "Was there a password guessing attack against the file server?"),
    ("GT9", "Was a new Windows service created on the file server?"),
    ("GT10", "Did they delete the backups before encrypting files?"),
    ("GT11", "Were logs wiped to cover their tracks?"),
    ("GT12", "Is there text in the logs that tries to manipulate an AI analyst?"),
    ("GT7", "是否从内存中窃取了密码？"),
    ("GT10", "攻击者是否删除了备份？"),
    ("GT3", "杀毒软件是否被关闭？"),
]


@dataclass
class QuestionResult:
    item: str
    question: str
    relevant: int
    first_rank: int | None  # 1-based, None if not in the top 20


def relevant_docs(index: EvidenceIndex, terms: list[str]) -> set[int]:
    terms = [t.lower() for t in terms]
    out = set()
    for doc_id, text in index._db.execute("SELECT id, text FROM docs"):
        low = text.lower()
        if all(t in low for t in terms):
            out.add(doc_id)
    return out


def evaluate(index: EvidenceIndex, answer_key: list[Any], *,
             questions: list[tuple[str, str]] | None = None, mode: str = "hybrid",
             depth: int = 20, rerank: bool = True) -> dict[str, Any]:
    key = {(k if isinstance(k, dict) else k.__dict__)["id"]:
           (k if isinstance(k, dict) else k.__dict__) for k in answer_key}
    results: list[QuestionResult] = []
    id_of = {row[1]: row[0] for row in index._db.execute("SELECT id, key FROM docs")}
    import json

    for item, q in questions or DEMO_QUESTIONS:
        rel = relevant_docs(index, key[item]["terms"])
        if not rel:
            continue
        hits = index.search(q, depth, mode=mode, rerank=rerank)
        rank = next((i for i, h in enumerate(hits, 1)
                     if id_of.get(json.dumps(h.key, default=str)) in rel), None)
        results.append(QuestionResult(item, q, len(rel), rank))
    n = len(results) or 1
    out: dict[str, Any] = {"mode": mode, "questions": len(results),
                           "embedder": index.embedder.name if index.embedder else None,
                           "reranker": index.reranker.name if index.reranker and rerank else None}
    for k in (1, 3, 5, 10):
        out[f"recall@{k}"] = round(sum(1 for r in results if r.first_rank and r.first_rank <= k)
                                   / n, 3)
    out["mrr"] = round(sum(1 / r.first_rank for r in results if r.first_rank) / n, 3)
    out["details"] = [r.__dict__ for r in results]
    return out


def to_markdown(rows: list[dict[str, Any]]) -> str:
    lines = ["| Search | Embedder | Reranker | recall@1 | recall@3 | recall@5 | recall@10 | MRR |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['mode']} | {r['embedder'] or '-'} | {r['reranker'] or '-'} "
                     f"| {r['recall@1']:.0%} | {r['recall@3']:.0%} | {r['recall@5']:.0%} "
                     f"| {r['recall@10']:.0%} | {r['mrr']:.2f} |")
    return "\n".join(lines) + "\n"
