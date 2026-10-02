"""The .glaive case file: one SQLite database that holds a whole investigation.

Contents:
  meta      key/value facts (schema version, case name, created/updated time)
  snapshot  the evidence graph and the finding report (zlib-compressed JSON)
  evidence  the evidence-store manifest (hash -> original name, size, format)
  audit     append-only log of who did what, when (ingest, findings, reviews)

The evidence files themselves stay in the evidence store folder next to the
case file (they can be gigabytes). The manifest records their SHA-256, so a
reopened case can verify that every file is still byte-identical.

SQLite was chosen because it is a single file, needs no server, works the
same on Windows/macOS/Linux, and survives crashes (each save is a transaction).
"""
from __future__ import annotations

import json
import sqlite3
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshot (name TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (sha256 TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


class CaseFileError(Exception):
    """Raised for unreadable or incompatible case files."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _pack(obj: Any) -> bytes:
    return zlib.compress(json.dumps(obj, separators=(",", ":")).encode("utf-8"), 6)


def _unpack(blob: bytes) -> Any:
    return json.loads(zlib.decompress(blob).decode("utf-8"))


class CaseFile:
    """Read/write access to one .glaive file."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        try:
            self._conn.executescript(_SCHEMA)
        except sqlite3.DatabaseError as e:
            self._conn.close()  # release the file (Windows locks open files)
            raise CaseFileError(f"{self.path} is not a GLAIVE case file: {e}") from e
        if not existed:
            self.set_meta("schema_version", str(SCHEMA_VERSION))
            self.set_meta("created_at", _now())
        version = int(self.get_meta("schema_version", "0"))
        if version > SCHEMA_VERSION:
            self._conn.close()
            raise CaseFileError(
                f"{self.path} was written by a newer GLAIVE (schema {version}); please upgrade."
            )

    # ---- meta ----------------------------------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def meta(self) -> dict[str, str]:
        return dict(self._conn.execute("SELECT key, value FROM meta").fetchall())

    # ---- snapshots -------------------------------------------------------------

    def write_snapshot(self, graph: dict[str, Any], report: dict[str, Any],
                       evidence: list[dict[str, Any]]) -> None:
        """Atomically replace the stored graph, findings and evidence manifest."""
        with self._conn:  # one transaction: all or nothing
            self._conn.execute("INSERT OR REPLACE INTO snapshot VALUES('graph', ?)", (_pack(graph),))
            self._conn.execute("INSERT OR REPLACE INTO snapshot VALUES('report', ?)",
                               (_pack(report),))
            self._conn.execute("DELETE FROM evidence")
            self._conn.executemany(
                "INSERT INTO evidence VALUES(?, ?)",
                [(e["evidence_hash"], json.dumps(e)) for e in evidence])
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('updated_at', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (_now(),))

    def read_snapshot(self, name: str) -> Any | None:
        row = self._conn.execute("SELECT data FROM snapshot WHERE name = ?", (name,)).fetchone()
        return _unpack(row[0]) if row else None

    def evidence(self) -> list[dict[str, Any]]:
        return [json.loads(r[0]) for r in self._conn.execute("SELECT data FROM evidence")]

    # ---- audit log -------------------------------------------------------------

    def append_audit(self, entries: list[dict[str, Any]]) -> None:
        with self._conn:
            self._conn.executemany(
                "INSERT INTO audit(ts, actor, action, detail) VALUES(?, ?, ?, ?)",
                [(e["ts"], e["actor"], e["action"], json.dumps(e.get("detail", {})))
                 for e in entries])

    def audit(self, limit: int = 1000) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT seq, ts, actor, action, detail FROM audit ORDER BY seq LIMIT ?", (limit,))
        return [{"seq": s, "ts": t, "actor": a, "action": ac, "detail": json.loads(d)}
                for s, t, a, ac, d in rows]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> CaseFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
