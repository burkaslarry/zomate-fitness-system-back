#!/usr/bin/env bash
# [F015][S006]
# Feature: Backend platform (FastAPI & PostgreSQL)
# Step: SRAA pre-deploy gate — Security Risk Assessment before Render production
# Logic: pip-audit on requirements.txt → block known vulns → pytest smoke.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  echo "Error: python3 or python not found in PATH." >&2
  exit 1
fi

echo "==> [SRAA] pip install runtime + audit tool"
"$PYTHON" -m pip install -q -U pip
"$PYTHON" -m pip install -q -r requirements.txt pip-audit

echo "==> [SRAA] pip-audit gate (requirements.txt)"
"$PYTHON" -m pip_audit -r requirements.txt

echo "==> [SRAA] pytest smoke"
"$PYTHON" -m pytest tests/test_health.py tests/test_keepalive.py -q

echo "==> [SRAA] Gate passed. Safe to deploy to Render."
