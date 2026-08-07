#!/usr/bin/env bash
set -euo pipefail

pcscd --foreground &
python /app/monitor.py &
exec gunicorn --bind "${BIND_HOST:-0.0.0.0}:${PORT:-8099}" --workers 2 --threads 4 server:app
