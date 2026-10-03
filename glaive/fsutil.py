"""File-system helpers."""
from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path


def remove_tree(path: Path) -> None:
    """shutil.rmtree that also removes read-only files (evidence copies are
    read-only, and Windows refuses to delete read-only files otherwise)."""

    def make_writable_and_retry(func, target, _exc):  # noqa: ANN001
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        func(target)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable_and_retry)
    else:
        shutil.rmtree(path, onerror=make_writable_and_retry)
