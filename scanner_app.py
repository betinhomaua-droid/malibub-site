from flask import Flask, request
import os, socket, subprocess, tempfile
from pathlib import Path

app=Flask(__name__)
app.config["MAX_CONTENT_LENGTH"]=512*1024*1024
TOKEN=os.getenv("SCANNER_TOKEN","")

def clamd_ping():
    with socket.create_connection(("127.0.0.1",3310),timeout=3) as s:
        s.sendall(b"zPING\0")
        data=s.recv(32)
    return b"PONG" in data

@app.get("/health")
def health():
    path=None
    try:
        if not clamd_ping():
            return {"status":"error","engine":"clamd","scan":"unavailable"},503
        with tempfile.NamedTemporaryFile(prefix="malibub_health_",suffix=".txt",delete=False) as tmp:
            path=tmp.name
            tmp.write(b"MALIBUB ClamAV health check")
        p=subprocess.run(
            ["clamdscan","--config-file=/etc/clamav/clamd.conf","--stream","--no-summary",path],
            capture_output=True,text=True,timeout=20
        )
        app.logger.info("clamd_health_scan_exit_code=%s",p.returncode)
        if p.returncode==0:
            return {"status":"ok","engine":"clamd","scan":"ok"},200
        return {"status":"error","engine":"clamd","scan":"failed"},503
    except Exception as exc:
        app.logger.error("clamd_health_error=%s",type(exc).__name__)
        return {"status":"error","engine":"clamd","scan":"failed"},503
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

@app.post("/scan")
def scan():
    if not TOKEN or request.headers.get("Authorization","")!="Bearer "+TOKEN:
        return {"status":"unauthorized"},401
    f=request.files.get("file")
    if not f or not f.filename:
        return {"status":"error","detail":"Arquivo ausente."},400
    path=None
    try:
        if not clamd_ping():
            return {"status":"error","detail":"Motor antivírus indisponível."},503
        suffix=Path(f.filename).suffix[:12]
        with tempfile.NamedTemporaryFile(prefix="malibub_scan_",suffix=suffix,delete=False) as tmp:
            path=tmp.name
            while True:
                chunk=f.stream.read(1024*1024)
                if not chunk:
                    break
                tmp.write(chunk)
        p=subprocess.run(
            ["clamdscan","--config-file=/etc/clamav/clamd.conf","--stream","--no-summary",path],
            capture_output=True,text=True,timeout=120
        )
        app.logger.info("clamdscan_exit_code=%s",p.returncode)
        output=(p.stdout or p.stderr or "").strip()
        if p.returncode==0:
            return {"status":"LIMPO","detail":"ClamAV: nenhuma ameaça detectada."},200
        if p.returncode==1:
            signature=output.rsplit(":",1)[-1].replace("FOUND","").strip()[:180]
            return {"status":"INFECTADO","detail":"ClamAV detectou ameaça: "+signature},200
        return {"status":"error","detail":"ClamAV não conseguiu concluir a análise."},503
    except subprocess.TimeoutExpired:
        app.logger.error("clamdscan_timeout")
        return {"status":"error","detail":"Tempo limite da varredura excedido."},503
    except Exception as exc:
        app.logger.error("scanner_internal_error=%s",type(exc).__name__)
        return {"status":"error","detail":"Falha interna do scanner."},503
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
