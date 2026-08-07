#!/usr/bin/env bash
set -euo pipefail

pcscd --foreground &
exec gunicorn --bind 127.0.0.1:8099 --workers 2 --threads 4 server:app

