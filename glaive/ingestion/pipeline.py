"""One-call ingestion: point GLAIVE at a file, folder or .zip and get a graph.

    summary = ingest_path(session, Path("./triage.zip"))

Steps:
  1. Collect files (folders walked; .zip archives safely extracted).
  2. Hash every file into the evidence store (chain of custody first).
  3. Detect each file's format from its bytes and read its events
     (EVTX binary, JSON / JSON-Lines exports).
  4. Parse ALL events in one pass, sorted by time, so a process seen in
     Security.evtx and Sysmon.evtx becomes one corroborated node.
  5. Run Sigma rules and correlation rules; each hit becomes an Alert node
     linked (Triggered edges) to the processes, users and hosts involved.
  6. Record everything in the session audit log.
"""
from __future__ import annotations

import logging
import os
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from glaive.detection.attack import tactics_of
from glaive.detection.correlations import (
    CorrelationHit,
    brute_force_then_success,
    prompt_injection_in_evidence,
    tamper_then_malicious,
)
from glaive.detection.sigma import SigmaEngine, SigmaRule, load_rules
from glaive.evidence.store import sniff_format
from glaive.graph.edges import Triggered
from glaive.graph.nodes import Alert
from glaive.ingestion.base import ParseResult
from glaive.ingestion.defender import DefenderEvtxParser
from glaive.ingestion.evtx_adapter import EvtxReadStats, iter_evtx_events
from glaive.ingestion.jsonl import iter_json_events
from glaive.ingestion.windows import (
    DEFENDER,
    WindowsEventParser,
    classify_channel,
    parse_time,
)

logger = logging.getLogger(__name__)

# Safety limits for archives (zip bombs, path traversal).
MAX_ARCHIVE_FILES = 50_000
MAX_ARCHIVE_BYTES = 16 * 1024**3
MAX_COMPRESSION_RATIO = 250
# Cap alerts per rule so a noisy community rule cannot flood the graph.
MAX_ALERTS_PER_RULE = 250

Progress = Callable[[str, dict[str, Any]], None]


class ArchiveError(Exception):
    """An archive was refused for safety reasons."""


@dataclass
class FileResult:
    path: str
    format: str
    status: str                      # ingested / skipped / error
    evidence_hash: str | None = None
    events: int = 0
    message: str = ""


@dataclass
class PipelineSummary:
    files: list[FileResult] = field(default_factory=list)
    events_total: int = 0
    events_by_family: dict[str, int] = field(default_factory=dict)
    nodes_added: int = 0
    edges_added: int = 0
    alerts: int = 0
    alerts_by_level: dict[str, int] = field(default_factory=dict)
    alerts_suppressed: int = 0
    alerts_merged: int = 0
    rules_loaded: int = 0
    rules_skipped: int = 0
    seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": [f.__dict__ for f in self.files],
            "events_total": self.events_total,
            "events_by_family": self.events_by_family,
            "nodes_added": self.nodes_added,
            "edges_added": self.edges_added,
            "alerts": self.alerts,
            "alerts_by_level": self.alerts_by_level,
            "alerts_suppressed": self.alerts_suppressed,
            "alerts_merged": self.alerts_merged,
            "rules_loaded": self.rules_loaded,
            "rules_skipped": self.rules_skipped,
            "seconds": round(self.seconds, 2),
        }


# ---- file collection -----------------------------------------------------------


def safe_extract(archive: Path, dest: Path) -> list[Path]:
    """Extract a zip with zip-slip, zip-bomb and symlink protection."""
    out: list[Path] = []
    dest = dest.resolve()
    with zipfile.ZipFile(archive) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ARCHIVE_FILES:
            raise ArchiveError(f"{archive.name}: too many files ({len(infos)})")
        total = sum(i.file_size for i in infos)
        if total > MAX_ARCHIVE_BYTES:
            raise ArchiveError(f"{archive.name}: uncompressed size {total} exceeds limit")
        compressed = sum(i.compress_size for i in infos) or 1
        if total / compressed > MAX_COMPRESSION_RATIO:
            raise ArchiveError(f"{archive.name}: compression ratio looks like a zip bomb")
        for info in infos:
            name = PurePosixPath(info.filename.replace("\\", "/"))
            if name.is_absolute() or ".." in name.parts or ":" in info.filename:
                raise ArchiveError(f"{archive.name}: unsafe path {info.filename!r}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks stored in the archive
            target = (dest / Path(*name.parts)).resolve()
            if dest not in target.parents:
                raise ArchiveError(f"{archive.name}: unsafe path {info.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
            out.append(target)
    return out


def collect_files(path: Path, work_dir: Path, session: Any = None) -> list[Path]:
    """Expand a path into evidence files (walk folders, extract zips)."""
    path = Path(path)
    if path.is_file():
        if zipfile.is_zipfile(path) and path.suffix.lower() == ".zip":
            sha = session.store.ingest(path) if session is not None else path.stem
            dest = work_dir / f"{path.stem}-{sha[:12]}"
            if session is not None:
                session.log("pipeline", "archive_extracted", archive=path.name, sha256=sha)
            files: list[Path] = []
            for f in safe_extract(path, dest):
                files.extend(collect_files(f, work_dir, session))
            return files
        return [path]
    files = []
    # Never ingest the case's own output (evidence copies, reports, extractions)
    own = session.analysis_dir.resolve() if session is not None else None
    for root, dirs, names in os.walk(path):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".")
                         and (own is None or (Path(root) / d).resolve() != own))
        for n in sorted(names):
            if not n.startswith("."):
                files.extend(collect_files(Path(root) / n, work_dir, session))
    return files


def read_events(path: Path) -> tuple[str, list[dict], str]:
    """Detect a file's format and read its events. Returns (format, events, note)."""
    fmt = sniff_format(path)
    if fmt == "evtx":
        stats = EvtxReadStats()
        events = list(iter_evtx_events(path, stats))
        note = f"{stats.backend}; {stats.records_skipped_malformed} malformed records skipped"
        return fmt, events, note
    if fmt in ("json", "jsonl"):
        stats: dict[str, int] = {}
        events = list(iter_json_events(path, stats))
        return fmt, events, f"{stats.get('records_skipped_malformed', 0)} malformed records skipped"
    return fmt, [], "unsupported format"


# ---- alerts --------------------------------------------------------------------


def _matched_fields(ev: dict, limit: int = 6) -> dict[str, str]:
    d = ev.get("raw_data") or {}
    preferred = ("Image", "NewProcessName", "CommandLine", "ParentImage", "ParentProcessName",
                 "TargetUserName", "SubjectUserName", "IpAddress", "DestinationIp",
                 "DestinationPort", "TargetObject", "Details", "TargetFilename", "ServiceName",
                 "ImagePath", "TaskName", "ScriptBlockText", "QueryName", "Threat Name")
    out = {}
    for k in preferred:
        v = d.get(k)
        if v:
            out[k] = v[:500]
        if len(out) >= limit:
            break
    return out


def _alert_node(ev: dict, rule_id: str, title: str, level: str, description: str,
                mitre: list[str], source: str, matched: dict[str, str] | None = None,
                tactics: list[str] | None = None) -> Alert | None:
    t = parse_time(ev.get("time_created"))
    if t is None or not ev.get("_evidence_hash"):
        return None
    return Alert(
        evidence_hash=ev["_evidence_hash"],
        derivation=f"{source} rule {rule_id} on {ev.get('_derivation', 'event')}",
        host_hostname=ev["computer"], rule_id=rule_id, title=title, level=level,
        detection_time=t, description=description or None, mitre_techniques=mitre,
        mitre_tactics=tactics if tactics is not None else tactics_of(mitre),
        event_id=ev.get("event_id"), event_record_id=ev.get("_record_id"),
        channel=ev.get("channel"), matched_fields=matched or _matched_fields(ev), source=source)


# ---- main entry point ------------------------------------------------------------


def ingest_path(
    session: Any,
    path: Path,
    *,
    sigma_paths: list[Path] | None = None,
    rules: list[SigmaRule] | None = None,
    progress: Progress | None = None,
) -> PipelineSummary:
    """Ingest a file, folder or zip into `session` (a GlaiveSession)."""
    started = datetime.now(UTC)
    summary = PipelineSummary()
    say = progress or (lambda stage, info: None)
    path = Path(path)
    if session.evidence_root is not None:
        try:
            path.resolve().relative_to(session.evidence_root)
        except ValueError as e:
            raise PermissionError(
                f"{path} is outside the allowed evidence root {session.evidence_root}") from e

    session.log("pipeline", "ingest_started", path=str(path))
    say("collect", {"path": str(path)})
    work_dir = session.analysis_dir / "extracted"
    files = collect_files(path, work_dir, session)

    # 1-3: custody + read
    all_events: list[dict] = []
    for f in files:
        try:
            sha = session.store.ingest(f)
            fmt, events, note = read_events(f)
        except (OSError, ValueError, ArchiveError) as e:
            summary.files.append(FileResult(str(f), "?", "error", message=str(e)))
            continue
        if not events:
            summary.files.append(FileResult(str(f), fmt, "skipped", sha, 0, note))
            session.log("pipeline", "file_stored_not_parsed", file=f.name, sha256=sha, format=fmt)
            continue
        reader = "EVTX" if fmt == "evtx" else "JSON"
        for i, ev in enumerate(events):
            rid = ev.get("_record_id")
            ev["_evidence_hash"] = sha
            ev["_derivation"] = f"{reader} {f.name} record {rid if rid is not None else i}"
            ev["_uid"] = f"{sha[:12]}:{rid if rid is not None else f'i{i}'}"
        all_events.extend(events)
        summary.files.append(FileResult(str(f), fmt, "ingested", sha, len(events), note))
        session.log("pipeline", "file_ingested", file=f.name, sha256=sha, format=fmt,
                    events=len(events))
        say("file", {"file": f.name, "events": len(events), "format": fmt})

    all_events.sort(key=lambda e: e.get("time_created") or "")
    summary.events_total = len(all_events)
    summary.events_by_family = dict(Counter(classify_channel(e) for e in all_events))

    # 4: parse
    say("parse", {"events": len(all_events)})
    defender_events = [e for e in all_events if classify_channel(e) == DEFENDER]
    other_events = [e for e in all_events if classify_channel(e) != DEFENDER]
    win = WindowsEventParser(session.store).parse(other_events)
    rep = session.orchestrator.integrate("WindowsEventParser", win)
    summary.nodes_added += rep.nodes_added
    summary.edges_added += rep.edges_added
    entities: dict[str, list[tuple[str, tuple]]] = dict(win.event_entities)

    if defender_events:
        dres = DefenderEvtxParser(session.store).parse(defender_events)
        drep = session.orchestrator.integrate("DefenderEvtxParser", dres)
        summary.nodes_added += drep.nodes_added
        by_identity = {(n.host_hostname, n.event_id, n.detection_time): n.canonical_key()
                       for n in dres.nodes}
        for ev in defender_events:
            k = by_identity.get((ev["computer"], ev["event_id"], parse_time(ev["time_created"])))
            if k and ev.get("_uid"):
                entities[ev["_uid"]] = [("detection", k), ("host", ("Host", ev["computer"]))]

    # 5: detections
    if rules is None:
        rules, rule_report = load_rules(sigma_paths)
        summary.rules_skipped = len(rule_report.skipped)
    summary.rules_loaded = len(rules)
    say("detect", {"rules": len(rules)})
    engine = SigmaEngine(rules)
    result = ParseResult()
    per_rule: Counter[str] = Counter()
    alert_records: list[dict] = []
    alert_links: list[tuple[Alert, str | None, list[str]]] = []

    # One alert per (rule, process): Sysmon 1 and Security 4688 both record the
    # same process creation, and both would otherwise fire the same rule.
    seen_rule_process: dict[tuple[str, tuple], Alert] = {}

    def add_alert(node: Alert | None, uid: str | None, related: list[str]) -> None:
        if node is None:
            return
        proc = next((k for role, k in entities.get(uid or "", []) if role == "process"), None)
        if proc is not None:
            prior = seen_rule_process.get((node.rule_id, proc))
            if prior is not None:
                prior.matched_fields.setdefault("CorroboratedBy", node.channel or "another log")
                summary.alerts_merged += 1
                return
            seen_rule_process[(node.rule_id, proc)] = node
        if per_rule[node.rule_id] >= MAX_ALERTS_PER_RULE:
            summary.alerts_suppressed += 1
            return
        per_rule[node.rule_id] += 1
        result.nodes.append(node)
        alert_links.append((node, uid, related))

    for ev in all_events:
        for rule in engine.match(ev):
            node = _alert_node(ev, rule.id, rule.title, rule.level, rule.description,
                               rule.mitre_techniques, "sigma", tactics=rule.mitre_tactics)
            add_alert(node, ev.get("_uid"), [])
            if node is not None:
                alert_records.append({"host": ev["computer"], "time": node.detection_time,
                                      "title": rule.title, "level": rule.level,
                                      "rule_id": rule.id, "description": rule.description,
                                      "event": ev})

    correlation_hits: list[CorrelationHit] = []
    correlation_hits += brute_force_then_success(all_events)
    correlation_hits += tamper_then_malicious(all_events, alert_records)
    correlation_hits += prompt_injection_in_evidence(all_events)
    for hit in correlation_hits:
        node = _alert_node(hit.anchor, hit.rule_id, hit.title, hit.level, hit.description,
                           hit.mitre, "correlation", hit.matched)
        add_alert(node, hit.anchor.get("_uid"), hit.related_uids)

    # Link alerts to the entities their events touched.
    for node, uid, related in alert_links:
        akey = node.canonical_key()
        targets: dict[tuple, str] = {}
        for u in [uid, *related]:
            for role, key in entities.get(u or "", []):
                targets.setdefault(key, role)
        targets.setdefault(("Host", node.host_hostname), "host")
        for key, role in targets.items():
            result.edges.append(Triggered(
                evidence_hash=node.evidence_hash, derivation=node.derivation,
                source_key=akey, target_key=key, role=role))

    arep = session.orchestrator.integrate("DetectionEngine", result)
    summary.nodes_added += arep.nodes_added
    summary.edges_added += arep.edges_added
    summary.alerts = len(alert_links)
    summary.alerts_by_level = dict(Counter(n.level for n, _, _ in alert_links))
    summary.seconds = (datetime.now(UTC) - started).total_seconds()

    session.log("pipeline", "ingest_finished", path=str(path), files=len(summary.files),
                events=summary.events_total, alerts=summary.alerts,
                nodes=session.graph.node_count(), edges=session.graph.edge_count())
    say("done", summary.to_dict())
    return summary
