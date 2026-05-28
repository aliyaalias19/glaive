"""Tool logic for the GLAIVE MCP server.

These are module-level functions that contain the actual work. The MCP tools
in server.py are thin closures that call these, passing the session. This
split lets us unit-test tool logic directly without an MCP transport.

Each function returns a plain dict (JSON-serializable) — the shape the agent
receives back.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

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

    # Validate path (M7 — basic guard; full sandboxing is Week 2)
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

# Supported filter operations (Decision M8).
_FILTER_OPS = {"eq", "contains", "gt", "lt", "exists"}

# Cap on results returned to the agent (Decision M9 — resource bound).
DEFAULT_QUERY_LIMIT = 100


def _matches_filter(node: Any, flt: dict[str, Any]) -> bool:
    """Evaluate one declarative filter against a node.

    A filter is {"field": str, "op": str, "value": Any}.
    Missing fields never match (except 'exists' with value False).
    Type mismatches (e.g. gt on a string) never match — they don't raise.
    """
    field = flt.get("field")
    op = flt.get("op")
    target = flt.get("value")

    if field is None or op not in _FILTER_OPS:
        return False

    has_field = hasattr(node, field)
    actual = getattr(node, field, None)

    if op == "exists":
        # value True -> field must be present and non-None; False -> absent/None
        present = has_field and actual is not None
        return present if target else not present

    if not has_field or actual is None:
        return False

    if op == "eq":
        return actual == target
    if op == "contains":
        try:
            return target in actual
        except TypeError:
            return False
    if op == "gt":
        try:
            return actual > target
        except TypeError:
            return False
    if op == "lt":
        try:
            return actual < target
        except TypeError:
            return False

    return False


def _node_summary(node: Any) -> dict[str, Any]:
    """Compact, JSON-safe summary of a node for the agent.

    Includes canonical_key (as a list, since JSON has no tuples), node_type,
    evidence_hash, and a small set of commonly useful display fields if present.
    """
    raw_key = node.canonical_key()
    # canonical_key may contain datetimes (identity tuples) -> make JSON-safe
    key = [
        (elem.isoformat() if hasattr(elem, "isoformat") else elem)
        for elem in raw_key
    ]
    summary: dict[str, Any] = {
        "canonical_key": key,
        "node_type": raw_key[0],
        "evidence_hash": getattr(node, "evidence_hash", None),
    }
    # Opportunistically include common display fields
    for field in ("name", "threat_name", "pid", "hostname", "host_hostname",
                  "path", "normalized_path", "action_taken", "detection_time"):
        if hasattr(node, field):
            val = getattr(node, field)
            if val is not None:
                # datetimes -> isoformat for JSON
                summary[field] = val.isoformat() if hasattr(val, "isoformat") else val
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
        limit: Max nodes to return (default 100, resource bound).

    Returns a dict with matched node summaries and counts.
    """
    filters = filters or []

    # Validate filters up front — give the agent clear feedback
    for flt in filters:
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
