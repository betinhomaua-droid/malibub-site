#!/bin/sh
set -eu
freshclam || true
clamd &
echo "Aguardando clamd..."
i=0
until clamdscan --ping 1 >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -gt 120 ]; then echo "clamd não iniciou"; exit 1; fi
  sleep 2
done
exec /opt/scanner-venv/bin/gunicorn --chdir /opt/malibub -b 0.0.0.0:${PORT:-10000} malware_scanner:app
