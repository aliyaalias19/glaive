"""A4 — Path traversal in ingest_artifact.

Attack: The agent (or an attacker who controls the agent's tool inputs)
calls ingest_artifact with a path that escapes the intended evidence
directory: '../../etc/passwd', '/etc/shadow', a symlink that points outside
the case folder.

A purely prompt-based defense would tell the agent 'please only ingest
files from the case directory.' A real defense rejects paths outside an
allowlist regardless of prompt.

Defense (architectural): When the session is constructed with
evidence_root=<dir>, do_ingest_artifact resolves the requested path
(following ../ and symlinks via Path.resolve()) and rejects it if the
resolved path is not under the allowlist.

Defense level: Strong WHEN evidence_root is set. The session permits a None
allowlist for backward compatibility and local development convenience —
that's an honest limitation, documented in BYPASS_TESTS.md and
LIMITATIONS.md.

See BYPASS_TESTS.md section A4 for the full defense narrative.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from glaive.mcp_server.session import GlaiveSession
from glaive.mcp_server.tools import do_ingest_artifact


pytestmark = pytest.mark.bypass


@pytest.fixture
def sandboxed_session(tmp_path: Path) -> tuple[GlaiveSession, Path]:
    """Session whose evidence_root is restricted to tmp_path/case.

    Returns (session, case_dir). The agent should only be able to ingest
    files under case_dir.
    """
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    session = GlaiveSession(
        analysis_dir=tmp_path / "analysis",
        evidence_root=case_dir,
    )
    return session, case_dir


class TestA4PathTraversal:
    def test_attack_dotdot_escape_rejected(
        self, sandboxed_session, tmp_path: Path
    ) -> None:
        """ATTACK: '../outside.txt' from within case_dir resolves outside the allowlist.

        DEFENSE: Path.resolve() canonicalizes the path; the allowlist
        comparison fails.
        """
        session, case_dir = sandboxed_session

        # Place a file outside the case dir
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"sensitive")

        # Attempt: traverse out of the case
        attack_path = str(case_dir / ".." / "outside.txt")
        result = do_ingest_artifact(session, attack_path, "defender_evtx")

        assert result["status"] == "error"
        assert result["error"] == "path_outside_allowlist"

    def test_attack_absolute_path_outside_rejected(
        self, sandboxed_session, tmp_path: Path
    ) -> None:
        """ATTACK: absolute path to a file outside the allowlist.

        DEFENSE: same as dotdot — the resolved absolute path isn't under
        evidence_root.
        """
        session, _ = sandboxed_session
        outside = tmp_path / "evil.evtx"
        outside.write_bytes(b"X" * 100)

        result = do_ingest_artifact(session, str(outside), "defender_evtx")
        assert result["status"] == "error"
        assert result["error"] == "path_outside_allowlist"

    def test_attack_symlink_escape_rejected(
        self, sandboxed_session, tmp_path: Path
    ) -> None:
        """ATTACK: place a symlink INSIDE the case dir pointing OUTSIDE it.

        DEFENSE: Path.resolve() follows symlinks; the resolved real path
        is outside evidence_root, so allowlist check fails.

        This is the most important variant. A naive defense that only
        checks the literal string path would be fooled here.
        """
        session, case_dir = sandboxed_session

        # The target outside the case dir
        target = tmp_path / "secret.txt"
        target.write_bytes(b"sensitive")

        # The symlink lives INSIDE the case dir but points outside
        link = case_dir / "looks_safe.evtx"
        try:
            os.symlink(target, link)
        except OSError as e:
            pytest.skip(f"Cannot create symlink in this environment: {e}")

        result = do_ingest_artifact(session, str(link), "defender_evtx")
        assert result["status"] == "error"
        assert result["error"] == "path_outside_allowlist"

    def test_legitimate_path_inside_allowlist_passes_path_check(
        self, sandboxed_session
    ) -> None:
        """CONTROL: a real file inside the allowlist passes the allowlist
        check (then proceeds to the parser, which may error for unrelated
        reasons — not our concern here).

        Proves the gate isn't arbitrarily harsh; it only blocks escapes.
        """
        session, case_dir = sandboxed_session
        good = case_dir / "good.evtx"
        # Real EVTX header magic so the parser doesn't blow up on empty mmap
        good.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)

        result = do_ingest_artifact(session, str(good), "defender_evtx")
        # The parser will reject this as malformed EVTX, but that's the
        # PARSER's verdict, not the allowlist's. What matters here is that
        # path_outside_allowlist is NOT the error.
        assert result.get("error") != "path_outside_allowlist"

    def test_no_allowlist_set_means_no_path_restriction(
        self, tmp_path: Path
    ) -> None:
        """CONTROL / HONEST LIMITATION: when evidence_root is None (default),
        the allowlist defense is OFF. This is documented in LIMITATIONS.md
        and noted in the A4 defense narrative — it's not a bug, it's a
        backward-compat default for development.

        This test pins the behavior so a future change is explicit, not
        accidental.
        """
        session = GlaiveSession(analysis_dir=tmp_path / "analysis")
        assert session.evidence_root is None

        # A file anywhere is reachable, allowlist-wise
        f = tmp_path / "anywhere.evtx"
        f.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)
        result = do_ingest_artifact(session, str(f), "defender_evtx")
        # path_outside_allowlist is NOT the error since no allowlist is set
        assert result.get("error") != "path_outside_allowlist"
