FROM clamav/clamav:1.4.6_base-debian13-slim
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/scanner-venv && /opt/scanner-venv/bin/pip install --no-cache-dir "Flask>=3.1,<4" "gunicorn>=23,<24"
RUN freshclam || true
RUN sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf 2>/dev/null || true
COPY scanner_app.py /app/scanner_app.py
WORKDIR /app
ENV PATH="/opt/scanner-venv/bin:$PATH"
CMD freshclam || true; freshclam -d -c 12 || true & clamd; exec gunicorn scanner_app:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --timeout 180
