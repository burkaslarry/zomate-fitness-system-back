#!/usr/bin/env bash
# [F015][S006]
# Feature: Backend platform (FastAPI & PostgreSQL)
# Step: SRAA pre-deploy gate — Security Risk Assessment before Render production
# Logic: pip-audit on requirements.txt → block known vulns → pytest smoke.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> [SRAA] pip install runtime + audit tool"
python -m pip install -q -U pip
python -m pip install -q -r requirements.txt pip-audit

echo "==> [SRAA] pip-audit gate (requirements.txt)"
python -m pip_audit -r requirements.txt

echo "==> [SRAA] pytest smoke"
python -m pytest tests/test_health.py tests/test_keepalive.py -q

echo "==> [SRAA] Gate passed. Safe to deploy to Render."
