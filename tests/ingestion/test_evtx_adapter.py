"""Tests for glaive/ingestion/evtx_adapter.py — the binary EVTX -> dict adapter.

Includes a real-evidence integration test that runs against test_evidence/Defender.evtx
if present. CI/judges without that file can still run the unit tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from glaive.ingestion.evtx_adapter import (
    EvtxReadStats,
    _clean_defender_path,
    _normalize_time_string,
    iter_evtx_events,
)


REAL_EVTX = Path(__file__).resolve().parents[2] / "test_evidence" / "Defender.evtx"


# =============================================================================
# Unit tests — pure-function helpers (no file required)
# =============================================================================


class TestNormalizeTimeString:
    def test_space_separator_converted_to_T(self) -> None:
        ts = "2025-04-12 08:21:44.894831+00:00"
        assert _normalize_time_string(ts) == "2025-04-12T08:21:44.894831+00:00"

    def test_already_iso_unchanged(self) -> None:
        ts = "2025-04-12T08:21:44.894831+00:00"
        assert _normalize_time_string(ts) == ts

    def test_only_first_space_replaced(self) -> None:
        """If there's somehow a second space in a time string, don't mangle it."""
        # Hypothetical edge case — shouldn't happen but verify behavior
        ts = "2025-04-12 08:21:44 extra"
        assert _normalize_time_string(ts) == "2025-04-12T08:21:44 extra"


class TestCleanDefenderPath:
    def test_strips_file_prefix(self) -> None:
        raw = "file:_C:\\Users\\USER\\Downloads\\foo.zip"
        assert _clean_defender_path(raw) == "C:\\Users\\USER\\Downloads\\foo.zip"

    def test_strips_webfile_prefix(self) -> None:
        raw = "webfile:_C:\\Users\\USER\\Downloads\\foo.zip|https://example.com/foo.zip|pid:123"
        # Returns up to but excluding any pipe/url remainder
        cleaned = _clean_defender_path(raw)
        # The webfile_ prefix is stripped; pipe-delimited extra stays
        assert cleaned.startswith("C:\\Users\\USER")

    def test_takes_first_of_semicolon_separated(self) -> None:
        raw = "file:_C:\\path\\one.zip; webfile:_C:\\path\\two.zip"
        assert _clean_defender_path(raw) == "C:\\path\\one.zip"

    def test_no_prefix_returned_as_is(self) -> None:
        raw = "C:\\plain\\path.exe"
        assert _clean_defender_path(raw) == "C:\\plain\\path.exe"

    def test_none_returns_none(self) -> None:
        assert _clean_defender_path(None) is None

    def test_empty_returns_none(self) -> None:
        assert _clean_defender_path("") is None


# =============================================================================
# Integration test — real Defender.evtx file
# =============================================================================


@pytest.fixture(scope="module")
def real_defender_events() -> tuple[list[dict], EvtxReadStats]:
    """Parse the real Defender.evtx ONCE per test module and cache.

    Without this, each integration test re-parses 16 MB of binary EVTX
    (~80s each). With this, the parse happens once and tests reuse results.
    """
    if not REAL_EVTX.exists():
        pytest.skip("Real Defender.evtx not present (test_evidence/ is gitignored).")
    stats = EvtxReadStats()
    events = list(iter_evtx_events(REAL_EVTX, stats))
    return events, stats


@pytest.mark.integration
@pytest.mark.skipif(
    not REAL_EVTX.exists(),
    reason="Real Defender.evtx not present (test_evidence/ is gitignored).",
)
class TestRealDefenderEvtx:
    """Integration tests against the real Defender.evtx file copied from Windows.

    Marked `integration` — skipped by default. Run explicitly with:
        pytest -m integration

    Skipped on fresh clones until the file is provided.
    """

    def test_file_parses_without_exception(self, real_defender_events) -> None:
        events, stats = real_defender_events
        assert stats.records_read > 0

    def test_supported_events_have_expected_shape(self, real_defender_events) -> None:
        events, _ = real_defender_events
        supported = {1116, 1117, 1118, 1119, 5001}
        for event in events:
            if event["event_id"] not in supported:
                continue
            assert isinstance(event["event_id"], int)
            assert isinstance(event["time_created"], str)
            assert "T" in event["time_created"]
            assert isinstance(event["computer"], str)
            assert event["computer"]
            assert "threat_name" in event
            assert "action" in event
            assert "file_path" in event
            assert "raw_data" in event
            assert isinstance(event["raw_data"], dict)

    def test_event_1116_has_threat_name(self, real_defender_events) -> None:
        events, _ = real_defender_events
        seen = False
        for event in events:
            if event["event_id"] == 1116:
                seen = True
                assert event["threat_name"] is not None
                assert event["threat_name"]
        assert seen, "Test file should contain at least one 1116 event"

    def test_file_paths_have_no_file_prefix(self, real_defender_events) -> None:
        events, _ = real_defender_events
        for event in events:
            if event["file_path"] is not None:
                assert not event["file_path"].startswith("file:_")
                assert not event["file_path"].startswith("webfile:_")

    def test_no_malformed_records_on_this_file(self, real_defender_events) -> None:
        _, stats = real_defender_events
        assert stats.records_skipped_malformed == 0


# =============================================================================
# Error handling
# =============================================================================


class TestErrorHandling:
    def test_missing_file_raises_filenotfound(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            list(iter_evtx_events(tmp_path / "does_not_exist.evtx"))
