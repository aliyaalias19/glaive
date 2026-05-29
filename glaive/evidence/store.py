"""GLAIVE content-addressed evidence store.

Files ingested via EvidenceStore are stored under a deterministic hash-based
filename. Every Node and Edge in the graph carries an `evidence_hash` field
that resolves to an entry in this store, giving any finding a traceable path
back to the original source bytes.

Design (DECISIONS.md I1-I4):
  I1 — Storage location: ./analysis/evidence_store/ (matches Protocol SIFT)
  I2 — Filename: <sha256>.<original_extension>
  I3 — Manifest: ./analysis/evidence_store/manifest.json
  I4 — Immutable: once stored, never overwrite (idempotent ingest)
"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


def hash_file(path: Path) -> str:
    """Compute SHA-256 of a file's content. Returns lowercase hex string.

    Streams the file in chunks so it works on large evidence (memory dumps,
    disk images) without loading into RAM.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidenceStore:
    """Content-addressed store for ingested evidence files.

    Usage:
        store = EvidenceStore(Path("./analysis/evidence_store"))
        sha = store.ingest(Path("./exports/evtx/Security.evtx"))
        # sha is now the evidence_hash to attach to any nodes/edges derived from this file.

        original_bytes = store.read(sha)
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._manifest_path = self.root / "manifest.json"
        self._manifest: dict[str, dict] = self._load_manifest()

    def _load_manifest(self) -> dict[str, dict]:
        """Load the manifest file if it exists, else return empty."""
        if self._manifest_path.exists():
            return json.loads(self._manifest_path.read_text())
        return {}

    def _save_manifest(self) -> None:
        """Write the manifest atomically (write to .tmp, then rename)."""
        tmp = self._manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._manifest, indent=2, sort_keys=True))
        tmp.replace(self._manifest_path)

    def ingest(self, source_path: Path) -> str:
        """Copy `source_path` into the store, keyed by its SHA-256.

        Returns the evidence_hash (sha256 hex string).

        Idempotent (I4): if a file with this hash is already stored, returns
        the hash without copying.
        """
        source_path = Path(source_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Cannot ingest: {source_path} does not exist")
        if not source_path.is_file():
            raise ValueError(f"Cannot ingest: {source_path} is not a regular file")

        sha = hash_file(source_path)

        # If we've already ingested this exact content, skip the copy
        if sha in self._manifest:
            return sha

        # Stored filename: <sha>.<extension>
        ext = source_path.suffix
        stored_path = self.root / f"{sha}{ext}"

        # Copy preserving metadata
        shutil.copy2(source_path, stored_path)

        # Record in manifest
        self._manifest[sha] = {
            "original_path": str(source_path),
            "original_name": source_path.name,
            "stored_path": str(stored_path),
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "size_bytes": source_path.stat().st_size,
        }
        self._save_manifest()

        return sha

    def has(self, sha: str) -> bool:
        """True if the store contains evidence with this hash."""
        return sha in self._manifest

    def get_path(self, sha: str) -> Path:
        """Return the on-disk path of stored evidence with this hash.

        Raises KeyError if the hash is not in the store.
        """
        if sha not in self._manifest:
            raise KeyError(f"Hash {sha[:16]}... not in evidence store")
        return Path(self._manifest[sha]["stored_path"])

    def read(self, sha: str) -> bytes:
        """Return the raw bytes of stored evidence with this hash."""
        path = self.get_path(sha)
        return path.read_bytes()

    def get_metadata(self, sha: str) -> dict:
        """Return manifest entry for the given hash (original name, size, etc)."""
        if sha not in self._manifest:
            raise KeyError(f"Hash {sha[:16]}... not in evidence store")
        return dict(self._manifest[sha])  # copy to prevent external mutation

    def list_all(self) -> list[dict]:
        """Return metadata for every file in the store.

        Each entry is {"evidence_hash", "original_name", "size_bytes",
        "ingested_at"}. Internal fields (e.g. stored_path) are not exposed.
        Order is not guaranteed; sort by ingested_at if needed.
        """
        return [
            {
                "evidence_hash": sha,
                "original_name": meta.get("original_name"),
                "size_bytes": meta.get("size_bytes"),
                "ingested_at": meta.get("ingested_at"),
            }
            for sha, meta in self._manifest.items()
        ]

    def __len__(self) -> int:
        return len(self._manifest)

    def __repr__(self) -> str:
        return f"EvidenceStore(root={self.root!r}, count={len(self)})"
