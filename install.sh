#!/usr/bin/env bash
# GLAIVE install script. Tested on SANS SIFT (WSL2 Ubuntu 22.04).
# Prerequisite: Protocol SIFT installed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "[GLAIVE] Verifying Python 3.11+..."
PYTHON_BIN=""
for candidate in python3.11 python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c "import sys; assert sys.version_info >= (3, 11)" 2>/dev/null; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done
if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: Python 3.11+ is required but not found on PATH."
    echo "       On Ubuntu 22.04: sudo add-apt-repository ppa:deadsnakes/ppa"
    echo "                        sudo apt install python3.11 python3.11-venv"
    exit 1
fi
echo "[GLAIVE] Using ${PYTHON_BIN}"

echo "[GLAIVE] Verifying Protocol SIFT is installed..."
if [ ! -f "${HOME}/.claude/CLAUDE.md" ]; then
    echo "  WARNING: ~/.claude/CLAUDE.md not found."
    echo "           Install Protocol SIFT first:"
    echo "           curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash"
fi

echo "[GLAIVE] Creating virtual environment in .venv/..."
"$PYTHON_BIN" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[GLAIVE] Upgrading pip..."
pip install --upgrade pip wheel >/dev/null

echo "[GLAIVE] Installing GLAIVE and dependencies (this takes ~2 minutes)..."
pip install -e ".[dev]"

echo "[GLAIVE] Verifying forensic primitives on PATH..."
for tool in vol log2timeline.py evtxexport rip.pl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "  WARNING: $tool not found on PATH. SIFT install may be incomplete."
    else
        echo "  OK: $tool"
    fi
done

echo ""
echo "[GLAIVE] Installation complete."
echo "  Activate the venv:    source .venv/bin/activate"
echo "  Set your API key:     export ANTHROPIC_API_KEY=sk-ant-..."
echo "  Run the demo:         glaive investigate evidence_samples/case1/"
