"""v0.2 regressions for the evidence store and ingest format checks."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from glaive.evidence.store import EvidenceStore, hash_file, sniff_format
from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.tools import do_ingest_artifact


def _make(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_stored_copy_is_read_only(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    sha = store.ingest(_make(tmp_path, "a.evtx", b"evidence bytes"))
    mode = store.get_path(sha).stat().st_mode
    assert not mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)


def test_stored_bytes_match_their_hash(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    sha = store.ingest(_make(tmp_path, "a.bin", os.urandom(3 * 1024 * 1024)))
    assert hash_file(store.get_path(sha)) == sha
    assert store.verify(sha) is True


def test_verify_detects_tampering(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    sha = store.ingest(_make(tmp_path, "a.bin", b"original"))
    stored = store.get_path(sha)
    os.chmod(stored, stat.S_IRUSR | stat.S_IWUSR)  # an attacker would do this first
    stored.write_bytes(b"tampered")
    assert store.verify(sha) is False
    assert store.verify_all() == {sha: False}


def test_no_temp_files_left_behind(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    src = _make(tmp_path, "a.bin", b"same")
    store.ingest(src)
    store.ingest(src)  # duplicate: temp copy must be cleaned up
    leftovers = [p.name for p in (tmp_path / "store").iterdir() if p.name.startswith(".ingest-")]
    assert leftovers == []
    assert len(store) == 1


def test_manifest_records_format(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    sha = store.ingest(_make(tmp_path, "x.evtx", b"ElfFile\x00" + b"\x00" * 64))
    assert store.list_all()[0]["format"] == "evtx"
    assert store.get_metadata(sha)["format"] == "evtx"


@pytest.mark.parametrize("data,expected", [
    (b"ElfFile\x00rest", "evtx"),
    (b"regf....", "registry_hive"),
    (b"MDMP....", "minidump"),
    (b"PK\x03\x04....", "zip"),
    (b"%PDF-1.7", "pdf"),
    (b'[{"a": 1}]', "json"),
    (b'{"a": 1}\n{"a": 2}\n', "jsonl"),
    (b"root:x:0:0:root:/root:/bin/bash\n", "text"),
    (b"\xff\xfe\x00\x81\x82", "binary"),
    (b"", "empty"),
])
def test_sniff_format(tmp_path: Path, data: bytes, expected: str) -> None:
    assert sniff_format(_make(tmp_path, "f", data)) == expected


def test_non_evtx_file_is_refused_and_not_stored(tmp_path: Path) -> None:
    """v0.1 accepted a passwd-like text file as Defender EVTX with status ok."""
    session = GlaiveSession(analysis_dir=tmp_path / "analysis")
    fake = _make(tmp_path, "passwd", b"root:x:0:0:root:/root:/bin/bash\n")
    r = do_ingest_artifact(session, str(fake), "defender_evtx")
    assert r["status"] == "error"
    assert r["error"] == "format_mismatch"
    assert len(session.store) == 0