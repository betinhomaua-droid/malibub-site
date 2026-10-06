from flask import Flask, request, jsonify
import os, socket, struct

app=Flask(__name__)
TOKEN=os.getenv("SCANNER_TOKEN","")
CLAMD_HOST=os.getenv("CLAMD_HOST","127.0.0.1")
CLAMD_PORT=int(os.getenv("CLAMD_PORT","3310"))

def scan_stream(stream):
    with socket.create_connection((CLAMD_HOST,CLAMD_PORT),timeout=10) as sock:
        sock.settimeout(180)
        sock.sendall(b"zINSTREAM\0")
        while True:
            chunk=stream.read(1024*1024)
            if not chunk: break
            sock.sendall(struct.pack(">I",len(chunk)))
            sock.sendall(chunk)
        sock.sendall(struct.pack(">I",0))
        reply=b""
        while b"\0" not in reply:
            data=sock.recv(4096)
            if not data: break
            reply+=data
    text=reply.replace(b"\0",b"").decode("utf-8","replace")
    if text.endswith(" OK"): return "LIMPO","ClamAV: arquivo limpo."
    if " FOUND" in text: return "INFECTADO","ClamAV: ameaça detectada."
    return "SUSPEITO","ClamAV: resultado inconclusivo; arquivo bloqueado."

@app.get("/health")
def health():
    try:
        with socket.create_connection((CLAMD_HOST,CLAMD_PORT),timeout=5) as s:
            s.sendall(b"zPING\0"); ok=b"PONG" in s.recv(64)
        return ({"status":"ok","clamav":"ready"},200) if ok else ({"status":"error"},503)
    except Exception: return {"status":"error","clamav":"unavailable"},503

@app.post("/scan")
def scan():
    if TOKEN and request.headers.get("Authorization")!="Bearer "+TOKEN: return {"status":"ERRO"},401
    f=request.files.get("file")
    if not f: return {"status":"ERRO","detail":"Arquivo ausente."},400
    try:
        status,detail=scan_stream(f.stream)
        return jsonify(status=status,detail=detail)
    except Exception:
        return {"status":"ERRO","detail":"ClamAV indisponível."},503
