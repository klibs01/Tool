#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
ulimit -n 65535 2>/dev/null || true
if [ ! -d .venv ]; then python3 -m venv .venv; fi
source .venv/bin/activate
pip install -q -r requirements.txt
exec uvicorn mcddos.main:app --host 0.0.0.0 --port 8000 --loop uvloop