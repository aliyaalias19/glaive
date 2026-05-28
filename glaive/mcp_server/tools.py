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
