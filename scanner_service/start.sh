#!/bin/sh
set -eu
freshclam || true
clamd &
i=0
until printf 'zPING\0' | nc 127.0.0.1 3310 2>/dev/null | grep -q PONG; do
  i=$((i+1))
  if [ "$i" -ge 120 ]; then echo "clamd failed to start"; exit 1; fi
  sleep 2
done
exec /opt/scanner-venv/bin/gunicorn --chdir /opt/scanner -b 0.0.0.0:${PORT:-10000} app:app
