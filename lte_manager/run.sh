#!/usr/bin/env bash
set -euo pipefail

pcscd --foreground &
python /app/monitor.py &
exec gunicorn --bind "${BIND_HOST:-0.0.0.0}:${PORT:-8099}" \
  --workers 1 --threads 4 --timeout 45 --graceful-timeout 15 --keep-alive 5 \
  --max-requests 2000 --max-requests-jitter 200 server:app
