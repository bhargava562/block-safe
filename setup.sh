#!/usr/bin/env bash
# ============================================================
# BlockSafe Setup Script (Linux / macOS / WSL)
# Requires: Python 3.11, pip
# ============================================================
set -euo pipefail

PYTHON_VERSION="3.11"
VENV_DIR="server/venv"
REQ_FILE="server/requirements.txt"

echo "============================================"
echo "  BlockSafe — Fresh Environment Setup"
echo "============================================"
echo ""

# ── 1. Locate Python 3.11 ──────────────────────────────────
PYTHON=""
for cmd in python3.11 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+')
        if [[ "$ver" == "$PYTHON_VERSION" ]]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python $PYTHON_VERSION not found."
    echo "Install it with:"
    echo "  Ubuntu/Debian: sudo apt install python${PYTHON_VERSION} python${PYTHON_VERSION}-venv"
    echo "  macOS:         brew install python@${PYTHON_VERSION}"
    echo "  Windows:       https://www.python.org/downloads/"
    exit 1
fi
echo "[OK] Found Python: $PYTHON ($($PYTHON --version))"

# ── 2. Remove old venv if exists ────────────────────────────
if [[ -d "$VENV_DIR" ]]; then
    echo "[..] Removing old virtual environment..."
    rm -rf "$VENV_DIR"
    echo "[OK] Old venv removed"
fi

# ── 3. Create fresh venv ────────────────────────────────────
echo "[..] Creating virtual environment with $PYTHON..."
"$PYTHON" -m venv "$VENV_DIR"
echo "[OK] Virtual environment created at $VENV_DIR"

# ── 4. Activate and upgrade pip ─────────────────────────────
source "$VENV_DIR/bin/activate"
echo "[..] Upgrading pip..."
pip install --upgrade pip --quiet
echo "[OK] pip upgraded to $(pip --version | awk '{print $2}')"

# ── 5. Install dependencies ────────────────────────────────
echo "[..] Installing dependencies from $REQ_FILE..."
pip install -r "$REQ_FILE" --quiet
echo "[OK] All dependencies installed"

# ── 6. Verify critical imports ──────────────────────────────
echo "[..] Verifying critical imports..."
python -c "
import fastapi, uvicorn, pydantic, langchain, numpy
print('[OK] Core imports verified')
"

# ── 7. Check .env file ──────────────────────────────────────
if [[ -f "server/.env" ]]; then
    echo "[OK] server/.env found"
else
    echo "[!!] server/.env NOT found — copy from server/.env.example and fill in your API keys"
    cp server/.env.example server/.env
    echo "     Created server/.env from template — EDIT IT with your actual keys"
fi

echo ""
echo "============================================"
echo "  Setup Complete!"
echo "============================================"
echo "  Activate:  source $VENV_DIR/bin/activate"
echo "  Run:       cd server && python run.py"
echo "  Test:      cd server && python -m pytest app/tests/ -v"
echo "  Docker:    docker compose up --build"
echo "============================================"
