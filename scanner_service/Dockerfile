FROM clamav/clamav:stable
USER root
RUN apk add --no-cache python3 py3-pip && python3 -m venv /opt/scanner-venv
COPY scanner_service/requirements.txt /tmp/requirements.txt
RUN /opt/scanner-venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt
COPY scanner_service/app.py /opt/scanner/app.py
COPY scanner_service/start.sh /opt/scanner/start.sh
RUN chmod +x /opt/scanner/start.sh
ENV CLAMD_HOST=127.0.0.1 CLAMD_PORT=3310 PORT=10000
EXPOSE 10000
CMD ["/opt/scanner/start.sh"]
