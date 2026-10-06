from flask import Flask, request
import os, subprocess, tempfile
from pathlib import Path

app=Flask(__name__)
app.config["MAX_CONTENT_LENGTH"]=512*1024*1024
TOKEN=os.getenv("SCANNER_TOKEN","")

def clamd_ready():
    p=subprocess.run(["clamdscan","--config-file=/etc/clamav/clamd.conf","--version"],capture_output=True,text=True,timeout=10)
    return p.returncode==0,(p.stdout or p.stderr or "").strip()[:160]

@app.get("/health")
def health():
    try:
        ok,version=clamd_ready()
        return ({"status":"ok","scanner":version,"engine":"clamd"},200) if ok else ({"status":"error","scanner":"unavailable"},503)
    except Exception:
        return {"status":"error","scanner":"unavailable"},503

@app.post("/scan")
def scan():
    if not TOKEN or request.headers.get("Authorization","")!="Bearer "+TOKEN:
        return {"status":"unauthorized"},401
    f=request.files.get("file")
    if not f or not f.filename:
        return {"status":"error","detail":"Arquivo ausente."},400
    suffix=Path(f.filename).suffix[:12]
    path=None
    try:
        with tempfile.NamedTemporaryFile(prefix="malibub_scan_",suffix=suffix,delete=False) as tmp:
            path=tmp.name
            while True:
                chunk=f.stream.read(1024*1024)
                if not chunk: break
                tmp.write(chunk)
        p=subprocess.run(["clamdscan","--config-file=/etc/clamav/clamd.conf","--no-summary",path],capture_output=True,text=True,timeout=120)
        output=(p.stdout or p.stderr or "").strip()
        if p.returncode==0:
            return {"status":"LIMPO","detail":"ClamAV: nenhuma ameaça detectada."},200
        if p.returncode==1:
            signature=output.rsplit(":",1)[-1].replace("FOUND","").strip()[:180]
            return {"status":"INFECTADO","detail":"ClamAV detectou ameaça: "+signature},200
        return {"status":"error","detail":"ClamAV não conseguiu concluir a análise."},503
    except subprocess.TimeoutExpired:
        return {"status":"error","detail":"Tempo limite da varredura excedido."},503
    finally:
        if path:
            try: os.unlink(path)
            except OSError: pass
