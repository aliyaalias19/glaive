"""Tool logic for the GLAIVE MCP server.

These are module-level functions that contain the actual work. The MCP tools
in server.py are thin closures that call these, passing the session. This
split lets us unit-test tool logic directly without an MCP transport.

Each function returns a plain dict (JSON-serializable) — the shape the agent
receives back.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from glaive.evidence.store import sniff_format
from glaive.graph.base import Node

from glaive.ingestion.defender import DefenderEvtxParser
from glaive.ingestion.evtx_adapter import iter_evtx_events
from glaive.mcp_server.session import GlaiveSession


# Supported source types for ingest_artifact (Decision M5).
SUPPORTED_SOURCE_TYPES = {"defender_evtx"}


def do_ingest_artifact(
    session: GlaiveSession, path: str, source_type: str
) -> dict[str, Any]:
    """Ingest one forensic artifact into the session's graph.

    Returns a result dict with status and stats. Never raises for expected
    error conditions (bad path, unsupported type) — returns an error dict
    instead, so the agent gets structured feedback it can act on.
    """
    # Validate source_type (M5)
    if source_type not in SUPPORTED_SOURCE_TYPES:
        return {
            "status": "error",
            "error": "unsupported_source_type",
            "message": (
                f"source_type '{source_type}' is not supported. "
                f"Supported: {sorted(SUPPORTED_SOURCE_TYPES)}."
            ),
        }

    # Validate path (M7 + A4 — allowlist when session.evidence_root is set)
    resolved = Path(path).expanduser()
    if not resolved.exists():
        return {
            "status": "error",
            "error": "file_not_found",
            "message": f"No file at path: {path}",
        }
    if not resolved.is_file():
        return {
            "status": "error",
            "error": "not_a_file",
            "message": f"Path is not a regular file: {path}",
        }
    # A4 defense: if session.evidence_root is set, the resolved path
    # (with symlinks followed) must be under it. resolve() handles
    # ../ traversal and symlink escapes uniformly.
    if session.evidence_root is not None:
        real_path = resolved.resolve()
        try:
            real_path.relative_to(session.evidence_root)
        except ValueError:
            return {
                "status": "error",
                "error": "path_outside_allowlist",
                "message": (
                    f"Path resolves to {real_path}, which is outside the "
                    f"session evidence_root ({session.evidence_root})."
                ),
            }

    # Format check (v0.2): v0.1 "ingested" any file, e.g. /etc/passwd, as a
    # Defender EVTX and copied it into the evidence store with status "ok".
    fmt = sniff_format(resolved)
    if source_type == "defender_evtx" and fmt != "evtx":
        return {
            "status": "error",
            "error": "format_mismatch",
            "message": f"{path} is not an EVTX file (detected format: {fmt}).",
        }

    # Dispatch by source_type
    if source_type == "defender_evtx":
        return _ingest_defender_evtx(session, resolved)

    # Unreachable (validated above), but keeps type-checkers happy
    return {
        "status": "error",
        "error": "internal",
        "message": "Unhandled source_type after validation.",
    }


def _ingest_defender_evtx(session: GlaiveSession, path: Path) -> dict[str, Any]:
    """Wire adapter -> parser -> orchestrator for a Defender EVTX file (M6)."""
    parser = DefenderEvtxParser(session.store)

    # Adapter: binary EVTX -> event dicts
    events = list(iter_evtx_events(path))

    # Orchestrator drives parse + graph integration + hashing
    report = session.orchestrator.run(
        parser, source_path=path, parse_input=events
    )

    return {
        "status": "ok",
        "source_type": "defender_evtx",
        "evidence_hash": report.evidence_hash,
        "records_read": len(events),
        "nodes_added": report.nodes_added,
        "nodes_merged": report.nodes_merged,
        "skipped_event_count": report.parser_stats.get("skipped_event_count", 0),
        "graph_totals": {
            "nodes": session.graph.node_count(),
            "edges": session.graph.edge_count(),
        },
    }


# =============================================================================
# query_graph
# =============================================================================

# Supported filter operations (Decision M8, extended in v0.2).
_FILTER_OPS = {"eq", "ne", "contains", "icontains", "gt", "gte", "lt", "lte", "exists", "in"}

# Cap on results returned to the agent (Decision M9 - resource bound).
DEFAULT_QUERY_LIMIT = 100
# Hard ceiling (v0.2). v0.1 had none: limit=99999999 was honoured.
MAX_QUERY_LIMIT = 500

# Matches strings that start like an ISO datetime: 2025-04-12T08:21 / 2025-04-12 08:21
_ISO_DT = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


def _queryable_fields() -> set[str]:
    """Public schema fields of every node type. Filters may only use these
    (v0.1 let the agent probe internals such as __class__ or model_config)."""
    out: set[str] = set()
    stack: list[type] = [Node]
    while stack:
        cls = stack.pop()
        for sub in cls.__subclasses__():
            stack.append(sub)
            out |= set(sub.model_fields)
    return out


def _coerce_filter_value(actual: Any, target: Any) -> Any:
    """JSON has no datetime type, so time filters arrive as ISO strings.
    Convert them so they can be compared with the node's real datetime
    (v0.1 compared str with datetime, which silently never matched)."""
    if isinstance(actual, datetime) and isinstance(target, str) and _ISO_DT.match(target):
        dt = datetime.fromisoformat(target.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return target


def _matches_filter(node: Any, flt: dict[str, Any]) -> bool:
    """Evaluate one declarative filter against a node.

    A filter is {"field": str, "op": str, "value": Any}.
    Missing fields never match (except 'exists' with value False).
    Type mismatches (e.g. gt on a string) never match - they don't raise.
    """
    field = flt.get("field")
    op = flt.get("op")
    target = flt.get("value")

    if field is None or op not in _FILTER_OPS:
        return False

    has_field = field in getattr(type(node), "model_fields", {})
    actual = getattr(node, field, None) if has_field else None

    if op == "exists":
        present = has_field and actual is not None
        return present if target else not present

    if not has_field or actual is None:
        return False

    if op == "in":
        return isinstance(target, list) and actual in target

    target = _coerce_filter_value(actual, target)
    try:
        if op == "eq":
            return actual == target
        if op == "ne":
            return actual != target
        if op == "contains":
            return target in actual
        if op == "icontains":
            return str(target).lower() in str(actual).lower()
        if op == "gt":
            return actual > target
        if op == "gte":
            return actual >= target
        if op == "lt":
            return actual < target
        if op == "lte":
            return actual <= target
    except TypeError:
        return False
    return False


def _json_safe(val: Any) -> Any:
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, bytes):
        return val.decode("utf-8", "replace")
    if isinstance(val, tuple):
        return [_json_safe(v) for v in val]
    return val


_SUMMARY_SKIP = {"evidence_hash", "derivation", "observed_at"}


def _node_summary(node: Any) -> dict[str, Any]:
    """Compact, JSON-safe summary of a node for the agent.

    v0.1 looked for fields named 'path' / 'normalized_path', which no node
    has, so File results never showed their path. v0.2 includes every field
    that has a value (long strings truncated) so the agent sees what the
    graph actually knows.
    """
    raw_key = node.canonical_key()
    summary: dict[str, Any] = {
        "canonical_key": [_json_safe(e) for e in raw_key],
        "node_type": raw_key[0],
        "evidence_hash": getattr(node, "evidence_hash", None),
    }
    for field in type(node).model_fields:
        if field in _SUMMARY_SKIP:
            continue
        val = getattr(node, field)
        if val is None or val == [] or val == {}:
            continue
        val = _json_safe(val)
        if isinstance(val, str) and len(val) > 300:
            val = val[:300] + "..."
        summary[field] = val
    return summary


def do_query_graph(
    session: GlaiveSession,
    node_type: str | None = None,
    filters: list[dict[str, Any]] | None = None,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> dict[str, Any]:
    """Query the evidence graph with declarative filters.

    Args:
        node_type: Optional node type to filter by (e.g. 'Process').
        filters: Optional list of {"field","op","value"} filters (AND-combined).
        limit: Max nodes to return (default 100, never more than 500).

    Returns a dict with matched node summaries and counts.
    """
    filters = filters or []
    limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
    allowed = _queryable_fields()

    # Validate filters up front - give the agent clear feedback
    for flt in filters:
        if not isinstance(flt, dict) or flt.get("field") not in allowed:
            bad = flt.get("field") if isinstance(flt, dict) else flt
            return {
                "status": "error",
                "error": "bad_filter_field",
                "message": f"Filter field {bad!r} is not a node schema field.",
            }
        if flt.get("op") not in _FILTER_OPS:
            return {
                "status": "error",
                "error": "bad_filter_op",
                "message": (
                    f"Filter op '{flt.get('op')}' not supported. "
                    f"Use one of: {sorted(_FILTER_OPS)}."
                ),
            }

    def predicate(node: Any) -> bool:
        return all(_matches_filter(node, f) for f in filters)

    matched = []
    total_matched = 0
    for node in session.graph.find_nodes(node_type=node_type, predicate=predicate):
        total_matched += 1
        if len(matched) < limit:
            matched.append(_node_summary(node))

    return {
        "status": "ok",
        "node_type": node_type,
        "filters_applied": filters,
        "total_matched": total_matched,
        "returned": len(matched),
        "truncated": total_matched > len(matched),
        "nodes": matched,
    }


# =============================================================================
# Key coercion (shared by tools that accept a canonical_key from the agent)
# =============================================================================


def _coerce_key_element(elem: Any) -> Any:
    """Convert an ISO-8601 *datetime* string back to a datetime; else passthrough.

    Only strings that look like a date AND a time are converted. v0.1 used
    bare fromisoformat, which also turned a hostname like '20240101' into a
    datetime and broke the lookup.
    """
    if isinstance(elem, str) and _ISO_DT.match(elem):
        try:
            return datetime.fromisoformat(elem.replace("Z", "+00:00"))
        except ValueError:
            return elem
    return elem


def _coerce_key(raw_key: list[Any] | tuple) -> tuple:
    """Coerce a canonical_key from the agent (a JSON list) back to a tuple."""
    return tuple(_coerce_key_element(e) for e in raw_key)


def resolve_key(session: GlaiveSession, raw_key: list[Any] | tuple) -> tuple:
    """Resolve an agent-supplied key: exact match first, then datetime-coerced."""
    raw = tuple(raw_key)
    if session.graph.has_node(raw):
        return raw
    return _coerce_key(raw_key)


# =============================================================================
# get_node_provenance
# =============================================================================


def do_get_node_provenance(
    session: GlaiveSession, canonical_key: list[Any]
) -> dict[str, Any]:
    """Return the full provenance chain for a single graph node.

    Args:
        canonical_key: The node's key (as returned by query_graph).

    Returns provenance: evidence_hash, derivation, observed_at, the evidence
    store metadata (original filename, size), observed_by for multi-source
    nodes, and display fields. This is the audit-trail tool.
    """
    key = resolve_key(session, canonical_key)

    if not session.graph.has_node(key):
        return {
            "status": "error",
            "error": "node_not_found",
            "message": (
                f"No node with key {list(canonical_key)}. "
                f"Use query_graph to obtain valid canonical_keys."
            ),
        }

    node = session.graph.get_node(key)

    # Core provenance fields (present on every node)
    evidence_hash = getattr(node, "evidence_hash", None)
    provenance: dict[str, Any] = {
        "status": "ok",
        "canonical_key": [
            (e.isoformat() if hasattr(e, "isoformat") else e) for e in key
        ],
        "node_type": key[0],
        "evidence_hash": evidence_hash,
        "derivation": getattr(node, "derivation", None),
    }

    observed_at = getattr(node, "observed_at", None)
    if observed_at is not None:
        provenance["observed_at"] = (
            observed_at.isoformat() if hasattr(observed_at, "isoformat") else observed_at
        )

    # Multi-source nodes carry observed_by
    observed_by = getattr(node, "observed_by", None)
    if observed_by:
        provenance["observed_by"] = list(observed_by)

    # Evidence store metadata — links hash back to the original file
    if evidence_hash and session.store.has(evidence_hash):
        meta = session.store.get_metadata(evidence_hash)
        provenance["source_evidence"] = {
            "original_name": meta.get("original_name"),
            "size_bytes": meta.get("size_bytes"),
            "ingested_at": meta.get("ingested_at"),
        }

    return provenance


# =============================================================================
# commit_finding — THE GATE (Decision M3, M11)
# =============================================================================


def do_commit_finding(
    session: GlaiveSession,
    claim: str,
    supporting_node_keys: list[list[Any]],
    confidence_hint: str = "suspected",
) -> dict[str, Any]:
    """Commit a finding to the investigation report — through the gate.

    The gate (FindingReport.can_commit) enforces:
      1. At least one supporting key
      2. Every supporting key resolves to a real graph node
      3. confidence_hint is checked against graph evidence; downgraded if
         the evidence doesn't justify it (never upgraded)

    On 'accepted' or 'downgraded_confidence', the finding IS committed
    (M11: a downgraded finding is still real, just less certain).
    On rejection, nothing is committed and the agent receives the reason.

    Returns the CommitDecision as a dict — the agent's self-correction signal.
    """
    # Validate confidence_hint
    valid_levels = {"confirmed", "suspected", "inferred", "disputed"}
    if confidence_hint not in valid_levels:
        return {
            "status": "error",
            "error": "bad_confidence_hint",
            "message": f"confidence_hint must be one of {sorted(valid_levels)}.",
        }

    # Coerce each supporting key (string datetimes -> datetimes) so graph
    # lookups in the gate succeed (reuses Step 5 infrastructure).
    coerced_keys = [resolve_key(session, k) for k in supporting_node_keys]

    decision = session.report.can_commit(
        claim=claim,
        supporting_node_keys=coerced_keys,
        confidence_hint=confidence_hint,  # type: ignore[arg-type]
        graph=session.graph,
    )

    # Commit on accept or downgrade (both carry a valid Finding)
    committed = False
    finding_id = None
    if decision.status in ("accepted", "downgraded_confidence") and decision.finding:
        session.report.commit(decision.finding)
        committed = True
        finding_id = decision.finding.finding_id

    result: dict[str, Any] = {
        "status": "ok" if committed else "rejected",
        "decision": decision.status,
        "reason": decision.reason,
        "committed": committed,
    }
    if finding_id:
        result["finding_id"] = finding_id
    if decision.agent_confidence_hint is not None:
        result["agent_confidence_hint"] = decision.agent_confidence_hint
    if decision.final_confidence is not None:
        result["final_confidence"] = decision.final_confidence
    if decision.grounding is not None:
        result["grounding"] = decision.grounding
    result["total_findings"] = len(session.report.findings)

    return result


# =============================================================================
# list_evidence
# =============================================================================


def do_list_evidence(session: GlaiveSession) -> dict[str, Any]:
    """List all evidence ingested into this investigation session.

    Returns each evidence file's hash, original name, size, ingest time, and
    how many ingest runs have happened. This is the chain-of-custody view.
    """
    items = session.store.list_all()

    # Sort by ingest time for a stable, chronological view
    items.sort(key=lambda x: x.get("ingested_at") or "")

    return {
        "status": "ok",
        "evidence_count": len(items),
        "ingest_runs": len(session.orchestrator.reports),
        "evidence": items,
        "graph_totals": {
            "nodes": session.graph.node_count(),
            "edges": session.graph.edge_count(),
        },
    }
