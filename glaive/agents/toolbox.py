"""The tools investigator agents can call, with validated arguments.

Each tool is a Pydantic model (its JSON Schema is what the model sees) plus
a handler. Arguments are validated before anything runs; invalid calls get
a structured error back so the model can correct itself. Results are JSON,
size-limited, and wrapped as untrusted data (spotlighting).
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from glaive.graph.wrapper import EvidenceGraph
from glaive.llm.types import ToolCall, ToolSpec
from glaive.mcp_server import tools as core
from glaive.security.injection import spotlight

MAX_RESULT_CHARS = 14_000
LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---- argument schemas -----------------------------------------------------------


class CaseOverviewArgs(BaseModel):
    """Summary of the case: hosts, evidence files, node counts and alert counts by rule."""


class ListAlertsArgs(BaseModel):
    """Detection-rule alerts, most severe first. Each has a canonical_key you can cite."""

    min_level: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    host: str | None = Field(None, description="Only alerts from this hostname.")
    rule_contains: str | None = Field(None, description="Case-insensitive filter on rule title.")
    limit: int = Field(25, ge=1, le=100)


class QueryGraphArgs(BaseModel):
    """Search graph nodes by type and field filters (AND-combined)."""

    node_type: str | None = Field(None, description=(
        "Process, User, Host, File, NetworkEndpoint, RegistryKey, Service, ScheduledTask, "
        "ScriptBlock, Alert, AntivirusDetection."))
    filters: list[dict[str, Any]] = Field(default_factory=list, description=(
        'List of {"field": ..., "op": ..., "value": ...}. ops: eq, ne, contains, icontains, '
        "gt, gte, lt, lte, exists, in. Times are ISO-8601 strings."))
    limit: int = Field(30, ge=1, le=100)


class NodeArgs(BaseModel):
    """Full details and provenance of one node."""

    canonical_key: list[Any] = Field(..., description="Exactly as returned by another tool.")


class NeighborsArgs(BaseModel):
    """Nodes directly connected to a node, with the relationship type and direction."""

    canonical_key: list[Any]
    edge_type: str | None = Field(None, description=(
        "Spawned, Connected, Wrote, Modified, Logon, AuthenticatedAs, Triggered, Persisted, "
        "References, Ran."))
    limit: int = Field(40, ge=1, le=150)


class TimelineArgs(BaseModel):
    """Chronological events (alerts, process starts, connections, logons...)."""

    start: str | None = Field(None, description="ISO-8601 start time.")
    end: str | None = Field(None, description="ISO-8601 end time.")
    host: str | None = None
    limit: int = Field(60, ge=1, le=200)


class CommitFindingArgs(BaseModel):
    """Record a forensic finding. It passes through the verification gate."""

    claim: str = Field(..., min_length=10, max_length=1200)
    supporting_node_keys: list[list[Any]] = Field(..., min_length=1, max_length=20)
    confidence_hint: Literal["confirmed", "suspected", "inferred"] = "suspected"
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    mitre_techniques: list[str] = Field(default_factory=list)
    rationale: str | None = Field(None, max_length=1200,
                                  description="Why the cited evidence supports the claim.")


class FinishArgs(BaseModel):
    """End the investigation with a short summary of the attack story."""

    summary: str = Field(..., min_length=10, max_length=4000)


# ---- helpers ---------------------------------------------------------------------


def _compact(node: Any) -> dict[str, Any]:
    s = core._node_summary(node)
    s.pop("evidence_hash", None)
    for k in ("text", "description"):
        if isinstance(s.get(k), str) and len(s[k]) > 400:
            s[k] = s[k][:400] + "..."
    return s


def _alert_row(node: Any) -> dict[str, Any]:
    return {"canonical_key": core._json_safe(node.canonical_key()), "title": node.title,
            "level": node.level, "host": node.host_hostname,
            "time": node.detection_time.isoformat(), "mitre": node.mitre_techniques,
            "fields": node.matched_fields}


class AgentToolbox:
    """Binds agent tools to a session. `readonly=True` removes commit/finish."""

    def __init__(self, session: Any, author: str = "hunter", readonly: bool = False) -> None:
        self.session = session
        self.author = author
        self.readonly = readonly
        self.finished: str | None = None
        self.commits: list[dict[str, Any]] = []
        self._tools: dict[str, tuple[type[BaseModel], Callable[[Any], Any]]] = {
            "case_overview": (CaseOverviewArgs, self._overview),
            "list_alerts": (ListAlertsArgs, self._alerts),
            "query_graph": (QueryGraphArgs, self._query),
            "get_node": (NodeArgs, self._node),
            "neighbors": (NeighborsArgs, self._neighbors),
            "timeline": (TimelineArgs, self._timeline),
        }
        if not readonly:
            self._tools["commit_finding"] = (CommitFindingArgs, self._commit)
            self._tools["finish"] = (FinishArgs, self._finish)

    @property
    def graph(self) -> EvidenceGraph:
        return self.session.graph

    def specs(self) -> list[ToolSpec]:
        out = []
        for name, (model, _) in self._tools.items():
            schema = model.model_json_schema()
            schema.pop("title", None)
            schema.pop("description", None)
            out.append(ToolSpec(name, (model.__doc__ or name).strip(), schema))
        return out

    def execute(self, call: ToolCall) -> str:
        """Run one tool call; always returns a (spotlighted) string."""
        if call.parse_error:
            payload: Any = {"error": "bad_arguments", "message": call.parse_error}
        elif call.name not in self._tools:
            payload = {"error": "unknown_tool", "message": f"No tool named {call.name!r}.",
                       "available": sorted(self._tools)}
        else:
            model, handler = self._tools[call.name]
            try:
                args = model.model_validate(call.arguments)
                payload = handler(args)
            except ValidationError as e:
                payload = {"error": "bad_arguments",
                           "message": json.loads(e.json(include_url=False))[:5]}
            except (KeyError, ValueError, TypeError) as e:
                payload = {"error": "tool_failed", "message": str(e)[:300]}
        text = json.dumps(payload, default=str, ensure_ascii=False)
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + '... [truncated: narrow your query]'
        return spotlight(text, "tool_result")

    # ---- handlers -------------------------------------------------------------------

    def _overview(self, _: CaseOverviewArgs) -> dict[str, Any]:
        g = self.graph
        alerts = list(g.find_nodes("Alert"))
        by_rule = Counter((a.level, a.title) for a in alerts)
        top = sorted(by_rule.items(), key=lambda kv: (-LEVEL_RANK.get(kv[0][0], 0), -kv[1]))
        hosts = sorted(n.hostname for n in g.find_nodes("Host"))
        times = [a.detection_time for a in alerts]
        return {
            "case": self.session.case_name,
            "hosts": hosts[:50],
            "node_counts": g.type_counts(),
            "evidence_files": [{"name": e["original_name"], "format": e.get("format")}
                               for e in self.session.store.list_all()][:40],
            "alert_time_range": [min(times).isoformat(), max(times).isoformat()] if times else None,
            "alerts_by_rule": [{"level": lvl, "title": t, "count": c} for (lvl, t), c in top[:40]],
            "findings_so_far": [{"id": f.short_id, "claim": f.claim[:200],
                                 "confidence": f.confidence}
                                for f in self.session.report.findings][-20:],
        }

    def _alerts(self, a: ListAlertsArgs) -> dict[str, Any]:
        floor = LEVEL_RANK[a.min_level]
        rows = [n for n in self.graph.find_nodes("Alert")
                if LEVEL_RANK.get(n.level, 0) >= floor
                and (a.host is None or n.host_hostname.lower() == a.host.lower())
                and (a.rule_contains is None or a.rule_contains.lower() in n.title.lower())]
        rows.sort(key=lambda n: (-LEVEL_RANK.get(n.level, 0), n.detection_time))
        return {"total": len(rows), "alerts": [_alert_row(n) for n in rows[:a.limit]]}

    def _query(self, a: QueryGraphArgs) -> dict[str, Any]:
        res = core.do_query_graph(self.session, a.node_type, a.filters, a.limit)
        if res.get("status") == "ok":
            for n in res["nodes"]:
                n.pop("evidence_hash", None)
        return res

    def _node(self, a: NodeArgs) -> dict[str, Any]:
        key = core.resolve_key(self.session, a.canonical_key)
        if not self.graph.has_node(key):
            return {"error": "node_not_found", "message": "Use a canonical_key returned by a tool."}
        prov = core.do_get_node_provenance(self.session, a.canonical_key)
        return {"node": _compact(self.graph.get_node(key)),
                "provenance": {k: prov.get(k) for k in
                               ("derivation", "observed_by", "source_evidence")}}

    def _neighbors(self, a: NeighborsArgs) -> dict[str, Any]:
        key = core.resolve_key(self.session, a.canonical_key)
        if not self.graph.has_node(key):
            return {"error": "node_not_found", "message": "Use a canonical_key returned by a tool."}
        rows = []
        for e in self.graph.outgoing_edges(key, a.edge_type):
            rows.append(("out", e, e.target_key))
        for e in self.graph.incoming_edges(key, a.edge_type):
            rows.append(("in", e, e.source_key))
        rows.sort(key=lambda r: (r[1].timestamp is None, r[1].timestamp or datetime.min))
        out = []
        for direction, e, other in rows[:a.limit]:
            item = {"edge": e.edge_type, "direction": direction,
                    "time": e.timestamp.isoformat() if e.timestamp else None,
                    "node": _compact(self.graph.get_node(other))}
            if hasattr(e, "confidence"):
                item["edge_confidence"] = e.confidence
                item["confirmed_by"] = e.confirmed_by
            out.append(item)
        return {"total": len(rows), "neighbors": out}

    def _timeline(self, a: TimelineArgs) -> dict[str, Any]:
        def ts(v: str | None) -> datetime | None:
            return core._coerce_filter_value(datetime.now().astimezone(), v) if v else None

        rows = self.graph.timeline(ts(a.start), ts(a.end), limit=5000)
        out = []
        for r in rows:
            if r["kind"] == "node":
                n = r["node"]
                host = getattr(n, "host_hostname", None) or getattr(n, "hostname", None)
                if a.host and host and host.lower() != a.host.lower():
                    continue
                label = getattr(n, "title", None) or getattr(n, "name", None) or \
                    getattr(n, "threat_name", None) or r["node_type"]
                out.append({"time": r["time"].isoformat(), "type": r["node_type"],
                            "label": label, "canonical_key": core._json_safe(r["key"])})
            else:
                if a.host and r["source"][1:2] and str(r["source"][1]).lower() != a.host.lower() \
                        and str(r["target"][1]).lower() != a.host.lower():
                    continue
                out.append({"time": r["time"].isoformat(), "type": r["edge_type"],
                            "from": core._json_safe(r["source"]),
                            "to": core._json_safe(r["target"])})
            if len(out) >= a.limit:
                break
        return {"returned": len(out), "events": out}

    def _commit(self, a: CommitFindingArgs) -> dict[str, Any]:
        res = core.do_commit_finding(
            self.session, a.claim, a.supporting_node_keys, a.confidence_hint,
            severity=a.severity, mitre_techniques=a.mitre_techniques, rationale=a.rationale,
            author=self.author)
        self.commits.append(res)
        return res

    def _finish(self, a: FinishArgs) -> dict[str, Any]:
        self.finished = a.summary
        return {"status": "ok", "message": "Investigation marked complete."}
