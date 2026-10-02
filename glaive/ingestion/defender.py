"""Parser for Windows Defender (Microsoft-Windows-Windows Defender/Operational) events.

Accepts event dicts as produced by glaive.ingestion.evtx_adapter.

Produces AntivirusDetection nodes for detection AND tamper events. Tamper
events (5001 real-time protection disabled, 5007 config changed, 5010/5012
scanning disabled) carry no threat name. v0.1 silently dropped them because
threat_name was mandatory, losing exactly the anti-forensics signal an
investigator most needs. They are now first-class nodes.

Provenance rule: a record without `_evidence_hash` is REJECTED (counted in
skipped_missing_provenance), never stamped with a placeholder hash. A node
whose hash does not resolve in the evidence store would be fabricated
provenance.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from pydantic import ValidationError

from glaive.graph.nodes import AntivirusDetection
from glaive.ingestion.base import Parser, ParseResult

logger = logging.getLogger(__name__)

# event_id -> human description. Detection events carry a threat name;
# tamper / health events do not.
EVENT_DESCRIPTIONS: dict[int, str] = {
    1006: "Malware detected (scan)",
    1007: "Action taken to protect system (scan)",
    1008: "Action to protect system failed",
    1015: "Suspicious behavior detected",
    1116: "Malware or potentially unwanted software detected",
    1117: "Action taken to protect system",
    1118: "Remediation action failed (non-critical)",
    1119: "Remediation action failed (critical)",
    5001: "Real-time protection disabled",
    5007: "Antimalware platform configuration changed",
    5010: "Scanning for malware and unwanted software disabled",
    5012: "Scanning for viruses disabled",
}

SUPPORTED_EVENT_IDS = set(EVENT_DESCRIPTIONS)

# Events that indicate defence evasion (ATT&CK T1562.001) rather than detection.
TAMPER_EVENT_IDS = {5001, 5007, 5010, 5012}


class DefenderParseResult(ParseResult):
    """ParseResult with extra stats specific to the Defender parser."""

    skipped_event_count: int = 0
    skipped_event_ids: list[int] = []
    skipped_malformed: int = 0
    skipped_missing_provenance: int = 0
    tamper_events: int = 0


class DefenderEvtxParser(Parser):
    """Parses Windows Defender event dicts into AntivirusDetection nodes.

    Source format: an iterable of dicts with keys
      event_id, time_created, computer, threat_name, action, file_path,
      raw_data (optional), _evidence_hash, _derivation
    """

    source_type = "Defender EVTX"

    def parse(self, source: Any) -> DefenderParseResult:
        if isinstance(source, (str, Path)):
            raise NotImplementedError(
                "Pass event dicts (use evtx_adapter.iter_evtx_events to read .evtx files)."
            )

        events: Iterable[dict] = source
        result = DefenderParseResult()

        for event_dict in events:
            event_id = event_dict.get("event_id")
            if event_id not in SUPPORTED_EVENT_IDS:
                result.skipped_event_count += 1
                if event_id is not None and event_id not in result.skipped_event_ids:
                    result.skipped_event_ids.append(event_id)
                continue

            if not event_dict.get("_evidence_hash"):
                result.skipped_missing_provenance += 1
                continue

            node = self._build_av_detection(event_dict)
            if node is None:
                result.skipped_malformed += 1
                continue
            if event_id in TAMPER_EVENT_IDS:
                result.tamper_events += 1
            result.nodes.append(node)

        return result

    def _build_av_detection(self, event_dict: dict) -> AntivirusDetection | None:
        """Convert one supported event dict into a node; None if malformed."""
        raw = event_dict.get("raw_data") or {}
        event_id = event_dict["event_id"]
        try:
            detection_time = self._parse_iso_utc(event_dict["time_created"])
            threat = event_dict.get("threat_name") or None
            if threat is None and event_id not in TAMPER_EVENT_IDS:
                # A detection event without a threat name is malformed.
                raise ValueError("detection event missing threat_name")
            return AntivirusDetection(
                evidence_hash=event_dict["_evidence_hash"],
                derivation=event_dict.get("_derivation", self._derivation()),
                host_hostname=event_dict["computer"],
                event_id=event_id,
                threat_name=threat,
                detection_time=detection_time,
                action_taken=event_dict.get("action"),
                file_path=event_dict.get("file_path"),
                event_description=EVENT_DESCRIPTIONS.get(event_id),
                severity=raw.get("Severity Name") or None,
                process_name=raw.get("Process Name") or None,
                detection_user=raw.get("Detection User") or None,
            )
        except (KeyError, ValueError, TypeError, ValidationError) as e:
            logger.debug("Skipping malformed Defender event %s: %s", event_id, e)
            return None

    def _parse_iso_utc(self, ts_str: str) -> datetime:
        """Parse ISO 8601 into tz-aware UTC. Naive timestamps are assumed UTC
        (EVTX SystemTime is always UTC)."""
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
