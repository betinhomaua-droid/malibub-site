from flask import Flask, request, jsonify
import os, subprocess, tempfile
from pathlib import Path

app=Flask(__name__)
TOKEN=os.getenv("SCANNER_TOKEN","")

@app.get("/health")
def health():
 return {"status":"ok"},200

@app.post("/scan")
def scan():
 auth=request.headers.get("Authorization","")
 if not TOKEN or auth!="Bearer "+TOKEN:
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
  p=subprocess.run(["clamscan","--no-summary","--infected",path],capture_output=True,text=True,timeout=180)
  output=(p.stdout or p.stderr or "").strip()
  if p.returncode==0: return {"status":"LIMPO","detail":"ClamAV: nenhuma ameaça detectada."},200
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
