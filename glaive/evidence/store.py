"""GLAIVE content-addressed evidence store.

Files ingested via EvidenceStore are stored under a deterministic hash-based
filename. Every Node and Edge in the graph carries an `evidence_hash` field
that resolves to an entry in this store, giving any finding a traceable path
back to the original source bytes.

Design (DECISIONS.md I1-I4):
  I1 - Storage location: ./analysis/evidence_store/ (matches Protocol SIFT)
  I2 - Filename: <sha256>.<original_extension>
  I3 - Manifest: ./analysis/evidence_store/manifest.json
  I4 - Immutable: once stored, never overwrite (idempotent ingest)

v0.2 hardening:
  - The file is hashed WHILE it is copied, so the stored bytes are exactly
    the hashed bytes (v0.1 hashed, then copied separately: a file changed in
    between was stored under a hash that did not match its content).
  - Stored copies are made read-only.
  - verify() / verify_all() re-hash stored evidence (chain-of-custody check).
  - sniff_format() identifies the evidence type from its first bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

# First bytes ("magic numbers") of evidence formats GLAIVE recognises.
_MAGIC: list[tuple[bytes, str]] = [
    (b"ElfFile\x00", "evtx"),
    (b"%PDF", "pdf"),
    (b"regf", "registry_hive"),
    (b"MDMP", "minidump"),
    (b"PK\x03\x04", "zip"),
    (b"EVF\x09\x0d\x0a\xff\x00", "ewf"),
    (b"EMiL", "lime"),
]


def sniff_format(path: Path) -> str:
    """Best-effort evidence format detection from the file's first bytes.

    Returns one of: evtx, pdf, registry_hive, minidump, zip, ewf, lime,
    json, jsonl, text, binary, empty.
    """
    with open(path, "rb") as f:
        head = f.read(4096)
    if not head:
        return "empty"
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    stripped = head.lstrip()
    if stripped[:1] == b"[":
        return "json"
    if stripped[:1] == b"{":
        first_line = stripped.split(b"\n", 1)[0].strip()
        if first_line.endswith(b"}") and b"\n" in stripped.strip():
            return "jsonl"
        return "json"
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def hash_file(path: Path) -> str:
    """Compute SHA-256 of a file's content. Returns lowercase hex string.

    Streams the file in chunks so it works on large evidence (memory dumps,
    disk images) without loading into RAM.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
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
        self._lock = threading.RLock()
        self._manifest: dict[str, dict] = self._load_manifest()

    def _load_manifest(self) -> dict[str, dict]:
        """Load the manifest file if it exists, else return empty."""
        if self._manifest_path.exists():
            return json.loads(self._manifest_path.read_text(encoding="utf-8"))
        return {}

    def _save_manifest(self) -> None:
        """Write the manifest atomically (write to .tmp, then rename)."""
        tmp = self._manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._manifest, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._manifest_path)

    def ingest(self, source_path: Path) -> str:
        """Copy `source_path` into the store, keyed by its SHA-256.

        Returns the evidence_hash (sha256 hex string).

        Idempotent (I4): if a file with this hash is already stored, returns
        the hash without storing a second copy.
        """
        source_path = Path(source_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Cannot ingest: {source_path} does not exist")
        if not source_path.is_file():
            raise ValueError(f"Cannot ingest: {source_path} is not a regular file")

        # Copy into a temp file inside the store, hashing every chunk as it
        # is written. The stored bytes are, by construction, the hashed bytes.
        h = hashlib.sha256()
        size = 0
        fd, tmp_name = tempfile.mkstemp(dir=self.root, prefix=".ingest-")
        try:
            with os.fdopen(fd, "wb") as out, open(source_path, "rb") as src:
                for chunk in iter(lambda: src.read(1 << 20), b""):
                    h.update(chunk)
                    out.write(chunk)
                    size += len(chunk)
            sha = h.hexdigest()

            with self._lock:
                if sha in self._manifest:  # identical content already stored
                    return sha

                stored_path = self.root / f"{sha}{source_path.suffix}"
                os.replace(tmp_name, stored_path)
                # Evidence is immutable: remove write permission.
                os.chmod(stored_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

                self._manifest[sha] = {
                    "original_path": str(source_path),
                    "original_name": source_path.name,
                    "stored_path": str(stored_path),
                    "ingested_at": datetime.now(timezone.utc).isoformat(),
                    "size_bytes": size,
                    "format": sniff_format(stored_path),
                }
                self._save_manifest()
            return sha
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def verify(self, sha: str) -> bool:
        """Re-hash stored evidence and confirm it still matches its address.

        Chain-of-custody check: detects tampering or corruption of the stored copy.
        """
        return hash_file(self.get_path(sha)) == sha

    def verify_all(self) -> dict[str, bool]:
        """Verify every stored file. Returns {sha: ok}."""
        return {sha: self.verify(sha) for sha in list(self._manifest)}

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
        return self.get_path(sha).read_bytes()

    def get_metadata(self, sha: str) -> dict:
        """Return manifest entry for the given hash (original name, size, etc)."""
        if sha not in self._manifest:
            raise KeyError(f"Hash {sha[:16]}... not in evidence store")
        return dict(self._manifest[sha])  # copy to prevent external mutation

    def list_all(self) -> list[dict]:
        """Return metadata for every file in the store.

        Each entry is {"evidence_hash", "original_name", "size_bytes",
        "ingested_at", "format"}. Internal fields (e.g. stored_path) are not
        exposed. Order is not guaranteed; sort by ingested_at if needed.
        """
        return [
            {
                "evidence_hash": sha,
                "original_name": meta.get("original_name"),
                "size_bytes": meta.get("size_bytes"),
                "ingested_at": meta.get("ingested_at"),
                "format": meta.get("format"),
            }
            for sha, meta in self._manifest.items()
        ]

    def __len__(self) -> int:
        return len(self._manifest)

    def __repr__(self) -> str:
        return f"EvidenceStore(root={self.root!r}, count={len(self)})"
