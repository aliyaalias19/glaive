"""GLAIVE web app: upload evidence, watch the investigation live, review findings.

    glaive serve ./my-case          # http://127.0.0.1:8765

Security defaults:
  - Binds to 127.0.0.1 only. If GLAIVE_WEB_TOKEN is set (or the server is
    started on a non-local address) every API call needs that token
    (header "X-Glaive-Token" or ?token=...).
  - Without a token, requests must be addressed to this computer (Host header
    127.0.0.1 / localhost / [::1], which defeats DNS rebinding) and any
    state-changing request sent by a browser must come from the app's own
    page (Origin check, which stops other websites posting forms to it).
  - Uploads are size-limited and filenames are sanitized; archives go through
    the safe extractor.
"""
from __future__ import annotations

import asyncio
import json
import os
import queue
import re
import secrets
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from glaive import __version__
from glaive.agents import Investigation
from glaive.agents.agents import numbered_findings, verify_cited_text
from glaive.ingestion.pipeline import ingest_path
from glaive.llm import Message, router_from_env
from glaive.llm.types import LLMError
from glaive.mcp_server import tools as core
from glaive.mcp_server.session import GlaiveSession
from glaive.reporting.html import render_html

STATIC = Path(__file__).parent / "static"
MAX_UPLOAD_BYTES = int(os.environ.get("GLAIVE_MAX_UPLOAD_MB", "2048")) * 1024 * 1024
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\- ]+")
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _hostname(netloc: str) -> str:
    """'127.0.0.1:8765' -> '127.0.0.1', '[::1]:8765' -> '[::1]'."""
    netloc = netloc.strip().lower()
    if netloc.startswith("["):
        return netloc.split("]", 1)[0] + "]"
    return netloc.rsplit(":", 1)[0]


# Set when the server starts shutting down, so open event streams (browser tabs)
# end at once instead of keeping Ctrl+C waiting.
shutting_down = threading.Event()


class LocalOnlyMiddleware:
    """Protection for the token-less local mode (plain ASGI, so streaming works).

    Rejects requests whose Host is not this computer (DNS rebinding), and
    browser requests that change state from another origin (cross-site
    request forgery: any website can make a browser POST a form here)."""

    def __init__(self, app: Any, allowed_hosts: frozenset[str] = LOCAL_HOSTS) -> None:
        self.app = app
        self.allowed = allowed_hosts

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                       for k, v in scope.get("headers", [])}
            ok = _hostname(headers.get("host", "")) in self.allowed
            origin = headers.get("origin")
            if ok and origin is not None and scope.get("method") not in _SAFE_METHODS:
                ok = _hostname(urlsplit(origin).netloc) in self.allowed
            if not ok:
                refused = PlainTextResponse(
                    "Request refused: the GLAIVE web app only accepts requests from this "
                    "computer. Set GLAIVE_WEB_TOKEN to allow remote access.", status_code=403)
                await refused(scope, receive, send)
                return
        await self.app(scope, receive, send)


class ReviewBody(BaseModel):
    approve: bool
    reviewer: str = "analyst"
    note: str | None = None
    override_confidence: str | None = None


class InvestigateBody(BaseModel):
    mode: str = "auto"  # auto | offline
    language: str = "en"
    max_steps: int = 30


class AskBody(BaseModel):
    question: str
    language: str = "en"


class _Job:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running: str | None = None
        self.last_error: str | None = None

    def start(self, name: str, fn: Any) -> None:
        with self.lock:
            if self.running:
                raise HTTPException(409, f"'{self.running}' is already running")
            self.running = name

        def run() -> None:
            try:
                fn()
                self.last_error = None
            except Exception as e:  # surfaced to the UI
                self.last_error = f"{name} failed: {e}"
            finally:
                with self.lock:
                    self.running = None

        threading.Thread(target=run, daemon=True).start()


def create_app(session: GlaiveSession, token: str | None = None) -> FastAPI:
    app = FastAPI(title="GLAIVE", version=__version__, docs_url="/api/docs")
    job = _Job()
    token = token or os.environ.get("GLAIVE_WEB_TOKEN") or None
    if not token:
        app.add_middleware(LocalOnlyMiddleware)

    def auth(request: Request) -> None:
        if not token:
            return
        supplied = request.headers.get("x-glaive-token") or request.query_params.get("token")
        if not supplied or not secrets.compare_digest(supplied, token):
            raise HTTPException(401, "missing or invalid token")

    guarded = [Depends(auth)]

    # ---- pages ---------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/report.html", response_class=HTMLResponse, dependencies=guarded)
    def report_html() -> str:
        return render_html(session)

    @app.get("/report.md", response_class=PlainTextResponse, dependencies=guarded)
    def report_md() -> str:
        return (session.summary_markdown or "") + "\n\n" + session.report.to_markdown()

    # ---- state -----------------------------------------------------------------------

    @app.get("/api/case", dependencies=guarded)
    def case() -> dict[str, Any]:
        router = router_from_env()
        return {"version": __version__, "stats": session.stats(),
                "summary_markdown": session.summary_markdown,
                "job": job.running, "last_error": job.last_error,
                "models": router.describe() if router else None}

    @app.get("/api/findings", dependencies=guarded)
    def findings() -> list[dict[str, Any]]:
        out = []
        for fid, f in numbered_findings(session):
            d = f.model_dump(mode="json", exclude={"supporting_node_keys"})
            d["ref"] = fid
            d["supporting_node_keys"] = [core._json_safe(tuple(k)) for k in f.supporting_node_keys]
            out.append(d)
        return out

    @app.post("/api/findings/{finding_id}/review", dependencies=guarded)
    def review(finding_id: str, body: ReviewBody) -> dict[str, Any]:
        try:
            f = session.report.review(finding_id, body.approve, body.reviewer[:80], body.note,
                                      body.override_confidence)  # type: ignore[arg-type]
        except KeyError as e:
            raise HTTPException(404, "no such finding") from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        session.save()
        return {"status": f.status, "confidence": f.confidence}

    @app.get("/api/alerts", dependencies=guarded)
    def alerts(min_level: str = "low", limit: int = 300) -> list[dict[str, Any]]:
        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        rows = [a for a in session.graph.find_nodes("Alert")
                if rank.get(a.level, 0) >= rank.get(min_level, 1)]
        rows.sort(key=lambda a: a.detection_time)
        return [{"key": core._json_safe(a.canonical_key()), "title": a.title, "level": a.level,
                 "host": a.host_hostname, "time": a.detection_time.isoformat(),
                 "mitre": a.mitre_techniques, "fields": a.matched_fields}
                for a in rows[:min(limit, 2000)]]

    @app.get("/api/node", dependencies=guarded)
    def node(key: str) -> dict[str, Any]:
        try:
            raw = json.loads(key)
        except json.JSONDecodeError as e:
            raise HTTPException(400, "key must be a JSON list") from e
        prov = core.do_get_node_provenance(session, raw)
        if prov.get("status") != "ok":
            raise HTTPException(404, prov.get("message", "not found"))
        k = core.resolve_key(session, raw)
        return {"summary": core._node_summary(session.graph.get_node(k)), "provenance": prov}

    @app.get("/api/graph", dependencies=guarded)
    def graph(focus: str = "findings", key: str | None = None, depth: int = 1,
              limit: int = 250) -> dict[str, Any]:
        g = session.graph
        seeds: list[tuple] = []
        if key:
            seeds = [core.resolve_key(session, json.loads(key))]
        elif focus == "findings":
            for f in session.report.findings:
                seeds.extend(tuple(k) for k in f.supporting_node_keys)
        if not seeds:  # fall back to alerts
            seeds = [a.canonical_key() for a in g.find_nodes("Alert")][:40]
        keys: set[tuple] = set()
        for s in seeds:
            if g.has_node(s):
                keys |= g.neighbors(s, depth=max(0, min(depth, 3)), max_nodes=limit)
            if len(keys) >= limit:
                break
        nodes, edges = g.subgraph(set(list(keys)[:limit]))
        return {
            "nodes": [{"id": json.dumps(core._json_safe(n.canonical_key())),
                       "type": n.node_type, "label": _label(n)} for n in nodes],
            "edges": [{"source": json.dumps(core._json_safe(e.source_key)),
                       "target": json.dumps(core._json_safe(e.target_key)),
                       "type": e.edge_type} for e in edges],
        }

    @app.get("/api/timeline", dependencies=guarded)
    def timeline(limit: int = 500) -> list[dict[str, Any]]:
        out = []
        for item in session.graph.timeline(limit=20000):
            if item["kind"] != "node":
                continue
            n = item["node"]
            out.append({"time": item["time"].isoformat(), "type": item["node_type"],
                        "label": _label(n), "host": getattr(n, "host_hostname", None),
                        "level": getattr(n, "level", None),
                        "key": core._json_safe(item["key"])})
        return out[-min(limit, 5000):]

    @app.get("/api/evidence", dependencies=guarded)
    def evidence() -> list[dict[str, Any]]:
        return sorted(session.store.list_all(), key=lambda e: e.get("ingested_at") or "")

    @app.post("/api/evidence/verify", dependencies=guarded)
    def verify() -> dict[str, Any]:
        results = session.store.verify_all()
        session.log("analyst", "evidence_verified", ok=sum(results.values()),
                    failed=[k for k, v in results.items() if not v])
        return {"ok": sum(results.values()), "failed": [k for k, v in results.items() if not v]}

    # ---- actions ---------------------------------------------------------------------

    @app.post("/api/upload", dependencies=guarded)
    async def upload(files: list[UploadFile] = File(...)) -> dict[str, Any]:
        dest = session.analysis_dir / "uploads" / secrets.token_hex(4)
        dest.mkdir(parents=True, exist_ok=True)
        total = 0
        saved = []
        for uf in files:
            name = _SAFE_NAME.sub("_", Path(uf.filename or "upload.bin").name)[:120] or "upload.bin"
            target = dest / name
            with open(target, "wb") as out:
                while chunk := await uf.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, "upload too large")
                    out.write(chunk)
            saved.append(name)
        job.start("ingest", lambda: (ingest_path(session, dest), session.save()))
        return {"saved": saved, "status": "ingesting"}

    @app.post("/api/investigate", dependencies=guarded)
    def investigate(body: InvestigateBody) -> dict[str, Any]:
        router = None if body.mode == "offline" else router_from_env()
        inv = Investigation(session, router, max_steps=min(body.max_steps, 80),
                            language=body.language if body.language in ("en", "zh") else "en")
        job.start("investigation", inv.run)
        return {"status": "started", "mode": "ai" if router else "offline"}

    @app.post("/api/ask", dependencies=guarded)
    def ask(body: AskBody) -> dict[str, Any]:
        return answer_question(session, body.question[:2000], body.language)

    @app.get("/api/events")
    async def events(request: Request, since: int = 0) -> StreamingResponse:
        auth(request)
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=5000)
        backlog = session.audit_log[since:]
        unsubscribe = session.subscribe(lambda e: q.put_nowait(e) if not q.full() else None)

        async def stream() -> Any:
            try:
                for e in backlog[-400:]:
                    yield f"data: {json.dumps(e, default=str)}\n\n"
                while not shutting_down.is_set() and not await request.is_disconnected():
                    try:
                        e = q.get_nowait()
                        yield f"data: {json.dumps(e, default=str)}\n\n"
                    except queue.Empty:
                        await asyncio.sleep(0.25)
                        yield ": keepalive\n\n"
            finally:
                unsubscribe()

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app


def _label(n: Any) -> str:
    for f in ("title", "name", "threat_name", "event_description", "hostname", "username",
              "service_name", "task_path", "value_name", "domain", "remote_addr", "full_path"):
        v = getattr(n, f, None)
        if v:
            return str(v)[:80]
    return n.node_type


def answer_question(session: GlaiveSession, question: str, language: str = "en") -> dict[str, Any]:
    """Ask-the-case: answers cite findings [F#]; uncited or ungrounded
    sentences are removed. Without a model, returns matching findings."""
    rows = numbered_findings(session)
    cites = dict(rows)
    stop = {"the", "and", "did", "was", "were", "has", "have", "what", "which", "who", "how",
            "any", "there", "this", "that", "with", "from", "into", "attacker", "case", "reach",
            "does", "are", "for", "when", "where", "why"}
    words = [w for w in re.findall(r"[\w.\-:\\/]{3,}", question.lower()) if w not in stop]
    scored = sorted(rows, key=lambda r: -sum(w in r[1].claim.lower() for w in words))
    relevant = [r for r in scored if any(w in r[1].claim.lower() for w in words)][:8]
    router = router_from_env()
    if router is None or not rows:
        lines = [f"- {f.claim} [{fid}]" for fid, f in (relevant or rows[:5])]
        return {"answer": "\n".join(lines) or "No findings yet.", "mode": "retrieval",
                "removed": []}
    if router.privacy is not None:
        router.privacy.learn_graph(session.graph)
    facts = "\n".join(f"[{fid}] ({f.severity}, {f.confidence}) {f.claim}" for fid, f in rows[:60])
    system = ("You answer questions about a forensic case using ONLY the findings listed. "
              "End every sentence with citations like [F3]. If the findings do not answer the "
              "question, say so in one sentence citing the closest finding, and suggest what "
              f"evidence would answer it. Reply in {'Simplified Chinese' if language == 'zh' else 'English'}.")
    try:
        resp = router.complete([Message.system(system),
                                Message.user(f"Findings:\n{facts}\n\nQuestion: {question}")],
                               None, max_tokens=900)
    except LLMError as e:
        return {"answer": f"Model unavailable: {e}", "mode": "error", "removed": []}
    text, kept, removed = verify_cited_text(resp.message.content or "", cites, session.graph)
    session.log("analyst", "question_answered", question=question[:300], kept=kept,
                removed=len(removed))
    return {"answer": text if kept else "The model's answer could not be verified against the "
            "evidence, so it was withheld.", "mode": "ai", "removed": removed}
