#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
PYTHON="${JUMP_PYTHON:-.venv/bin/python}"
"$PYTHON" -m jump_ssh.cli migrate
exec "$PYTHON" -m uvicorn jump_ssh.main:create_app --factory --host "${BIND_ADDRESS:-0.0.0.0}" --port "${PORT:-8200}" --workers 1 --no-proxy-headers --ws-max-size 32768
