"""Parser for Windows Defender EVTX events.

For Day 4 (P2 decision): accepts pre-parsed event dicts. Day 5 will add a
thin binary EVTX -> dict layer using python-evtx.

Produces AntivirusDetection nodes for events in the supported set:
  - 1116 (malware detected)
  - 1117 (action taken)
  - 1118 (remediation started)
  - 1119 (remediation succeeded)
  - 5001 (real-time protection disabled)

Other event IDs are skipped silently (logged in skip_count for the caller).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from glaive.graph.nodes import AntivirusDetection
from glaive.ingestion.base import Parser, ParseResult


# Supported Defender event IDs and the schema Principle 1 evidence chain
SUPPORTED_EVENT_IDS = {1116, 1117, 1118, 1119, 5001}


class DefenderParseResult(ParseResult):
    """ParseResult with extra stats specific to the Defender parser."""

    skipped_event_count: int = 0
    skipped_event_ids: list[int] = []


class DefenderEvtxParser(Parser):
    """Parses pre-extracted Windows Defender event dicts into
    AntivirusDetection nodes.

    Source format: an iterable of dicts with these keys:
      event_id, time_created, computer, threat_name, action, file_path

    For Day 5: a thin upstream layer reads binary .evtx and yields this dict
    shape. Today we accept the dicts directly.
    """

    source_type = "Defender EVTX"

    def parse(self, source: Any) -> DefenderParseResult:
        """Parse an iterable of Defender event dicts.

        The `source` parameter is either:
          - A Path to a precomputed dict-list (JSON, future)
          - A list/iterable of dicts (today)

        For testability today, we accept any iterable.
        """
        if isinstance(source, (str, Path)):
            raise NotImplementedError(
                "Binary EVTX file parsing is a Day 5 task. "
                "Pass an iterable of pre-parsed event dicts for now."
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

            node = self._build_av_detection(event_dict)
            if node is not None:
                result.nodes.append(node)

        return result

    def _build_av_detection(self, event_dict: dict) -> AntivirusDetection | None:
        """Convert a single supported event dict into an AntivirusDetection node.

        Returns None if the dict is malformed (missing required fields).
        """
        try:
            detection_time = self._parse_iso_utc(event_dict["time_created"])
            return AntivirusDetection(
                evidence_hash=event_dict.get("_evidence_hash", "f" * 64),
                derivation=event_dict.get("_derivation", self._derivation()),
                host_hostname=event_dict["computer"],
                event_id=event_dict["event_id"],
                threat_name=event_dict["threat_name"],
                detection_time=detection_time,
                action_taken=event_dict.get("action"),
                file_path=event_dict.get("file_path"),
            )
        except (KeyError, ValueError) as e:
            # Malformed event — skip it. (Day 5 will add proper logging.)
            return None

    def _parse_iso_utc(self, ts_str: str) -> datetime:
        """Parse an ISO 8601 datetime string, normalized to UTC tz-aware.

        Supports both '+00:00' and 'Z' UTC formats.
        """
        # Python's fromisoformat accepts '+00:00' but not 'Z' in 3.10
        # In 3.11+ it accepts both.
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
