"""Tests for glaive/evidence/store.py — content-addressed evidence store.

Verifies:
  - Hash computation is correct (SHA-256, lowercase hex, 64 chars)
  - Ingestion produces deterministic hashes (same bytes -> same hash)
  - Idempotency: re-ingesting same file is a no-op
  - Manifest is persistent (survives recreating EvidenceStore on same root)
  - Retrieval (get_path, read, get_metadata) works
  - Errors are raised for missing files / unknown hashes
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from glaive.evidence.store import EvidenceStore, hash_file


# Known test fixture: 5 lowercase letters
KNOWN_CONTENT = b"hello"
KNOWN_SHA256 = hashlib.sha256(KNOWN_CONTENT).hexdigest()


# ---- hash_file --------------------------------------------------------------


class TestHashFile:
    def test_hash_of_known_content(self, tmp_path: Path) -> None:
        f = tmp_path / "hello.txt"
        f.write_bytes(KNOWN_CONTENT)
        assert hash_file(f) == KNOWN_SHA256

    def test_hash_is_lowercase_hex_64_chars(self, tmp_path: Path) -> None:
        f = tmp_path / "any.txt"
        f.write_bytes(b"any content here")
        h = hash_file(f)
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_of_empty_file(self, tmp_path: Path) -> None:
        """SHA-256 of empty input has a well-known value."""
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        assert hash_file(f) == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_hash_streaming_handles_large(self, tmp_path: Path) -> None:
        """File larger than chunk size still hashes correctly."""
        f = tmp_path / "big.bin"
        # 200KB — exceeds the 65KB read chunk
        content = b"A" * (200 * 1024)
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert hash_file(f) == expected


# ---- EvidenceStore — basic mechanics ----------------------------------------


class TestEvidenceStoreBasics:
    def test_creates_root_directory(self, tmp_path: Path) -> None:
        root = tmp_path / "store"
        assert not root.exists()
        EvidenceStore(root)
        assert root.exists()
        assert root.is_dir()

    def test_initially_empty(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        assert len(store) == 0

    def test_repr_contains_count(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        assert "count=0" in repr(store)

    def test_ingest_known_content(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "hello.evtx"
        source.write_bytes(KNOWN_CONTENT)

        sha = store.ingest(source)

        assert sha == KNOWN_SHA256
        assert len(store) == 1
        assert store.has(sha)

    def test_ingest_preserves_extension(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "Security.evtx"
        source.write_bytes(KNOWN_CONTENT)

        sha = store.ingest(source)
        stored_path = store.get_path(sha)
        assert stored_path.suffix == ".evtx"

    def test_ingest_missing_file_raises(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        with pytest.raises(FileNotFoundError):
            store.ingest(tmp_path / "does_not_exist.evtx")

    def test_ingest_directory_raises(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        a_dir = tmp_path / "subdir"
        a_dir.mkdir()
        with pytest.raises(ValueError):
            store.ingest(a_dir)


# ---- Idempotency (I4) -------------------------------------------------------


class TestIdempotency:
    def test_reingesting_same_file_returns_same_hash(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "hello.txt"
        source.write_bytes(KNOWN_CONTENT)

        sha1 = store.ingest(source)
        sha2 = store.ingest(source)
        assert sha1 == sha2
        assert len(store) == 1  # no duplicate stored

    def test_two_files_same_content_get_same_hash(self, tmp_path: Path) -> None:
        """Two different source paths with identical bytes => one stored entry."""
        store = EvidenceStore(tmp_path / "store")
        src_a = tmp_path / "a.txt"
        src_b = tmp_path / "b.txt"
        src_a.write_bytes(KNOWN_CONTENT)
        src_b.write_bytes(KNOWN_CONTENT)

        sha_a = store.ingest(src_a)
        sha_b = store.ingest(src_b)
        assert sha_a == sha_b
        assert len(store) == 1


# ---- Manifest persistence ---------------------------------------------------


class TestManifestPersistence:
    def test_manifest_written_after_ingest(self, tmp_path: Path) -> None:
        root = tmp_path / "store"
        store = EvidenceStore(root)
        source = tmp_path / "file.txt"
        source.write_bytes(KNOWN_CONTENT)
        store.ingest(source)

        manifest = root / "manifest.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert KNOWN_SHA256 in data

    def test_manifest_survives_recreating_store(self, tmp_path: Path) -> None:
        """A new EvidenceStore instance on the same root sees prior ingests."""
        root = tmp_path / "store"
        store_a = EvidenceStore(root)
        source = tmp_path / "file.txt"
        source.write_bytes(KNOWN_CONTENT)
        sha = store_a.ingest(source)

        # New instance, same root
        store_b = EvidenceStore(root)
        assert store_b.has(sha)
        assert len(store_b) == 1


# ---- Retrieval --------------------------------------------------------------


class TestRetrieval:
    def test_read_returns_original_bytes(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "evidence.bin"
        source.write_bytes(KNOWN_CONTENT)
        sha = store.ingest(source)

        retrieved = store.read(sha)
        assert retrieved == KNOWN_CONTENT

    def test_get_path_returns_stored_path(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "evidence.bin"
        source.write_bytes(KNOWN_CONTENT)
        sha = store.ingest(source)

        stored = store.get_path(sha)
        assert stored.exists()
        assert stored.read_bytes() == KNOWN_CONTENT

    def test_get_metadata_contains_original_name(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "Security.evtx"
        source.write_bytes(KNOWN_CONTENT)
        sha = store.ingest(source)

        meta = store.get_metadata(sha)
        assert meta["original_name"] == "Security.evtx"
        assert meta["size_bytes"] == len(KNOWN_CONTENT)
        assert "ingested_at" in meta

    def test_get_metadata_returns_copy(self, tmp_path: Path) -> None:
        """External mutation of returned dict doesn't corrupt the store."""
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "x.bin"
        source.write_bytes(KNOWN_CONTENT)
        sha = store.ingest(source)

        meta = store.get_metadata(sha)
        meta["original_name"] = "hacked"

        # Internal manifest still correct
        fresh = store.get_metadata(sha)
        assert fresh["original_name"] != "hacked"

    def test_unknown_hash_raises_keyerror(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        with pytest.raises(KeyError):
            store.read("0" * 64)
        with pytest.raises(KeyError):
            store.get_path("0" * 64)
        with pytest.raises(KeyError):
            store.get_metadata("0" * 64)


# =============================================================================
# list_all() public API
# =============================================================================


class TestListAll:
    def test_empty_store_returns_empty_list(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        assert store.list_all() == []

    def test_single_file_lists_with_metadata(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "evidence.bin"
        source.write_bytes(KNOWN_CONTENT)
        sha = store.ingest(source)

        items = store.list_all()
        assert len(items) == 1
        item = items[0]
        assert item["evidence_hash"] == sha
        assert item["original_name"] == "evidence.bin"
        assert item["size_bytes"] == len(KNOWN_CONTENT)
        assert "ingested_at" in item

    def test_does_not_expose_internal_fields(self, tmp_path: Path) -> None:
        """list_all() must not leak the on-disk stored_path (internal detail)."""
        store = EvidenceStore(tmp_path / "store")
        source = tmp_path / "x.bin"
        source.write_bytes(KNOWN_CONTENT)
        store.ingest(source)
        item = store.list_all()[0]
        assert "stored_path" not in item

    def test_multiple_files_listed(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "store")
        for name, content in [("a.bin", b"alpha"), ("b.bin", b"beta"), ("c.bin", b"gamma")]:
            f = tmp_path / name
            f.write_bytes(content)
            store.ingest(f)
        items = store.list_all()
        assert len(items) == 3
        names = {item["original_name"] for item in items}
        assert names == {"a.bin", "b.bin", "c.bin"}
