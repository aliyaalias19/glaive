"""Audit trail: every model call, tool call and agent run, as trace spans.

In forensics it must be possible to show afterwards how a conclusion was
reached. During an investigation GLAIVE writes one JSON line per span to
<case>/trace.jsonl: what ran, in which order, how long it took, which model
answered, how many tokens it used, and what the verification gate decided.

Span and attribute names follow the OpenTelemetry semantic conventions for
generative AI (gen_ai.operation.name, gen_ai.request.model,
gen_ai.usage.input_tokens, gen_ai.tool.name ...), so the file reads like any
other trace. Prompt and response text are NOT recorded (they hold case data);
only their sizes are.

To also send the spans to Jaeger, Grafana Tempo, Langfuse, Phoenix or any
OpenTelemetry backend:

    pip install "glaive[otel]"
    set OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

    with tracing(case_dir / "trace.jsonl"):
        with span("invoke_agent hunter", **{"gen_ai.agent.name": "hunter"}) as s:
            s.set("glaive.steps", 12)
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import secrets
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_current_tracer: contextvars.ContextVar[Tracer | None] = contextvars.ContextVar(
    "glaive_tracer", default=None)
_current_span: contextvars.ContextVar[Span | None] = contextvars.ContextVar(
    "glaive_span", default=None)


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_id: str | None
    start: float
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    error: str | None = None
    end: float | None = None
    _otel: Any = None

    def set(self, key: str, value: Any) -> None:
        if value is None:
            return
        self.attributes[key] = value
        if self._otel is not None:
            with contextlib.suppress(Exception):
                self._otel.set_attribute(key, value if isinstance(value, (str, bool, int, float))
                                         else json.dumps(value, default=str))

    def fail(self, error: BaseException | str) -> None:
        self.status = "error"
        self.error = str(error)[:300]

    def to_dict(self) -> dict[str, Any]:
        end = self.end if self.end is not None else time.time()
        return {"trace_id": self.trace_id, "span_id": self.span_id,
                "parent_id": self.parent_id, "name": self.name,
                "start": datetime.fromtimestamp(self.start, UTC).isoformat(),
                "duration_ms": round((end - self.start) * 1000, 1), "status": self.status,
                "error": self.error, "attributes": self.attributes}


class Tracer:
    """Writes finished spans to a JSON Lines file (and to OpenTelemetry if set up)."""

    def __init__(self, path: Path | None) -> None:
        self.path = Path(path) if path else None
        self.trace_id = secrets.token_hex(16)
        self.spans: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._otel = _otel_tracer()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, s: Span) -> None:
        row = s.to_dict()
        with self._lock:
            self.spans.append(row)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")


_OTEL_STATE: dict[str, Any] = {}


def _otel_tracer() -> Any:
    """An OpenTelemetry tracer when the SDK is installed and an OTLP endpoint
    is configured; otherwise None (GLAIVE never requires OpenTelemetry)."""
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") and \
            not os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        return None
    if "tracer" in _OTEL_STATE:
        return _OTEL_STATE["tracer"]
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        _OTEL_STATE["tracer"] = None
        return None
    provider = TracerProvider(resource=Resource.create({"service.name": "glaive"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    _OTEL_STATE["provider"] = provider
    _OTEL_STATE["tracer"] = trace.get_tracer("glaive")
    return _OTEL_STATE["tracer"]


@contextlib.contextmanager
def tracing(path: Path | None) -> Iterator[Tracer]:
    """Make a tracer current for the code inside the block."""
    tracer = Tracer(path)
    token = _current_tracer.set(tracer)
    try:
        yield tracer
    finally:
        _current_tracer.reset(token)
        provider = _OTEL_STATE.get("provider")
        if provider is not None:
            with contextlib.suppress(Exception):
                provider.force_flush(5_000)


def current_tracer() -> Tracer | None:
    return _current_tracer.get()


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[Span]:
    """A span under the current one. Without a current tracer it still works
    (attributes are kept on the object) but nothing is written."""
    tracer = _current_tracer.get()
    parent = _current_span.get()
    s = Span(name=name, trace_id=tracer.trace_id if tracer else "", span_id=secrets.token_hex(8),
             parent_id=parent.span_id if parent else None, start=time.time())
    otel_cm = None
    if tracer is not None and tracer._otel is not None:
        with contextlib.suppress(Exception):
            otel_cm = tracer._otel.start_as_current_span(name)
            s._otel = otel_cm.__enter__()
    for k, v in attributes.items():
        s.set(k, v)
    token = _current_span.set(s)
    try:
        yield s
    except BaseException as e:
        s.fail(e)
        raise
    finally:
        _current_span.reset(token)
        s.end = time.time()
        if otel_cm is not None:
            with contextlib.suppress(Exception):
                if s.status == "error":
                    from opentelemetry.trace import Status, StatusCode

                    s._otel.set_status(Status(StatusCode.ERROR, s.error or ""))
                otel_cm.__exit__(None, None, None)
        if tracer is not None:
            tracer.record(s)


def read_trace(path: Path) -> list[dict[str, Any]]:
    """Spans from a trace.jsonl file (unreadable lines are skipped)."""
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def summarize(spans: list[dict[str, Any]]) -> dict[str, Any]:
    """Totals an auditor asks for first: model calls and tokens per model,
    tool calls per tool, gate decisions, errors."""
    models: dict[str, dict[str, float]] = {}
    tools: dict[str, int] = {}
    gate: dict[str, int] = {}
    errors = 0
    for s in spans:
        a = s.get("attributes", {})
        op = a.get("gen_ai.operation.name")
        errors += s.get("status") == "error"
        if op == "chat":
            m = f"{a.get('gen_ai.provider.name', '?')}:{a.get('gen_ai.response.model') or a.get('gen_ai.request.model', '?')}"
            row = models.setdefault(m, {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                                        "ms": 0.0})
            row["calls"] += 1
            row["input_tokens"] += int(a.get("gen_ai.usage.input_tokens") or 0)
            row["output_tokens"] += int(a.get("gen_ai.usage.output_tokens") or 0)
            row["ms"] += float(s.get("duration_ms") or 0)
        elif op == "execute_tool":
            tools[a.get("gen_ai.tool.name", "?")] = tools.get(a.get("gen_ai.tool.name", "?"), 0) + 1
            if a.get("glaive.gate.decision"):
                d = str(a["glaive.gate.decision"])
                gate[d] = gate.get(d, 0) + 1
    return {"spans": len(spans), "errors": errors, "models": models, "tools": tools,
            "gate_decisions": gate,
            "investigations": sum(1 for s in spans if s.get("name") == "investigation")}
