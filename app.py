from flask import Flask, request, redirect, url_for, session, flash, render_template_string, send_from_directory, send_file, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape as html_escape
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from zoneinfo import ZoneInfo
import time
from pathlib import Path
import os, uuid, io, secrets, zipfile, base64
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import boto3
import requests

app=Flask(__name__)
APP_ENV=os.getenv("APP_ENV","production")
SECRET_KEY=os.getenv("SECRET_KEY")
DATABASE_URL=os.getenv("DATABASE_URL")
if APP_ENV=="production" and (not SECRET_KEY or not DATABASE_URL):
 raise RuntimeError("Production requires SECRET_KEY and DATABASE_URL.")
app.config["SECRET_KEY"]=SECRET_KEY or "malibub-homologacao"
app.config["SQLALCHEMY_DATABASE_URI"]=DATABASE_URL or "sqlite:///malibub.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
AUTO_PURGE_DAYS=int(os.getenv("AUTO_PURGE_DAYS","90"))
AUTO_PURGE_INTERVAL_SECONDS=int(os.getenv("AUTO_PURGE_INTERVAL_SECONDS","86400"))
MALWARE_SCANNER_URL=os.getenv("MALWARE_SCANNER_URL","").rstrip("/")
MALWARE_SCANNER_TOKEN=os.getenv("MALWARE_SCANNER_TOKEN","")
MALWARE_SCAN_REQUIRED=os.getenv("MALWARE_SCAN_REQUIRED","false").lower()=="true"
app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
app.config["SESSION_COOKIE_SECURE"]=APP_ENV=="production"
app.config["PERMANENT_SESSION_LIFETIME"]=timedelta(hours=8)
TURNSTILE_SITE_KEY=os.getenv("TURNSTILE_SITE_KEY","").strip()
TURNSTILE_SECRET_KEY=os.getenv("TURNSTILE_SECRET_KEY","").strip()
if APP_ENV=="production" and bool(TURNSTILE_SITE_KEY)!=bool(TURNSTILE_SECRET_KEY):
 raise RuntimeError("Both Turnstile keys must be configured together")

def verify_turnstile(token):
 if not TURNSTILE_SECRET_KEY: return APP_ENV!="production" or not TURNSTILE_SITE_KEY
 if not isinstance(token,str) or not token or len(token)>2048: return False
 try:
  response=requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify",data={"secret":TURNSTILE_SECRET_KEY,"response":token,"remoteip":request.remote_addr},timeout=8)
  return response.ok and response.json().get("success") is True
 except (requests.RequestException,ValueError):
  app.logger.warning("turnstile_verification_unavailable")
  return False

DIRECT_UPLOAD_SIGNER=URLSafeTimedSerializer(app.config["SECRET_KEY"],salt="malibub-direct-upload-v2")
db=SQLAlchemy(app)
UPLOAD=Path(app.instance_path)/"uploads"; UPLOAD.mkdir(parents=True,exist_ok=True)
R2_BUCKET=os.getenv("R2_BUCKET","")
R2_ENDPOINT_URL=os.getenv("R2_ENDPOINT_URL","")
def object_storage_enabled():
 return all([R2_BUCKET,R2_ENDPOINT_URL,os.getenv("R2_ACCESS_KEY_ID"),os.getenv("R2_SECRET_ACCESS_KEY")])
def r2_client():
 return boto3.client("s3",endpoint_url=R2_ENDPOINT_URL,aws_access_key_id=os.getenv("R2_ACCESS_KEY_ID"),aws_secret_access_key=os.getenv("R2_SECRET_ACCESS_KEY"),region_name="auto")
# R2 lifecycle and browser CORS are intentionally administered in Cloudflare.
# Application credentials remain limited to object operations; do not grant bucket-admin rights here.
def store_upload(fileobj,key,content_type=None):
 if object_storage_enabled():
  extra={"ContentType":content_type} if content_type else {}
  r2_client().upload_fileobj(fileobj,R2_BUCKET,key,ExtraArgs=extra or None)
 else: fileobj.save(UPLOAD/key)
def storage_bytes(key):
 if object_storage_enabled():
  return r2_client().get_object(Bucket=R2_BUCKET,Key=key)["Body"].read()
 return (UPLOAD/key).read_bytes()
def storage_delete(key):
 if object_storage_enabled(): r2_client().delete_object(Bucket=R2_BUCKET,Key=key)
 else:
  p=UPLOAD/key
  if p.exists(): p.unlink()
def purge_expired_exam_files(days=None):
 days=int(days or AUTO_PURGE_DAYS)
 cutoff=datetime.utcnow()-timedelta(days=days)
 exams=Exam.query.filter(Exam.created_at < cutoff).all()
 exam_ids=[e.id for e in exams]
 if not exam_ids:
  app.logger.info("retention_cleanup_complete days=%s examined=0 deleted=0 failed=0",days)
  return {"examined":0,"deleted":0,"failed":0}
 files=ExamFile.query.filter(ExamFile.exam_id.in_(exam_ids)).all()
 deleted=0; failed=0
 for item in files:
  try:
   if item.stored: storage_delete(item.stored)
   db.session.delete(item)
   db.session.commit()
   deleted+=1
  except Exception as exc:
   db.session.rollback(); failed+=1
   app.logger.error("retention_cleanup_file_failed file_id=%s error_type=%s",item.id,type(exc).__name__)
 app.logger.info("retention_cleanup_complete days=%s examined=%s deleted=%s failed=%s",days,len(files),deleted,failed)
 return {"examined":len(files),"deleted":deleted,"failed":failed}

def storage_exists(key):
 if object_storage_enabled():
  try: r2_client().head_object(Bucket=R2_BUCKET,Key=key); return True
  except Exception as exc:
   if str(getattr(exc,'response',{}).get('Error',{}).get('Code','')) in {'404','NoSuchKey','NotFound'}: return False
   raise
 return (UPLOAD/key).exists()
def storage_response(key,name=None,download=False):
 if object_storage_enabled():
  obj=r2_client().get_object(Bucket=R2_BUCKET,Key=key)
  body=obj["Body"]
  safe_name=secure_filename(name or Path(key).name) or "arquivo"
  disposition="attachment" if download else "inline"
  def generate():
   try:
    while True:
     chunk=body.read(1024*1024)
     if not chunk: break
     yield chunk
   finally:
    body.close()
  response=Response(stream_with_context(generate()),content_type=obj.get("ContentType") or "application/octet-stream")
  response.headers["Content-Disposition"]=f'{disposition}; filename="{safe_name}"'
  if obj.get("ContentLength") is not None: response.headers["Content-Length"]=str(obj["ContentLength"])
  response.headers["Cache-Control"]="no-store, private"
  return response
 return send_from_directory(UPLOAD,key,as_attachment=download,download_name=name or Path(key).name)

def validate_zip_upload(fileobj):
 pos=fileobj.stream.tell()
 try:
  with zipfile.ZipFile(fileobj.stream) as archive:
   members=archive.infolist()
   if len(members)>2000: return False,"ZIP com quantidade excessiva de arquivos."
   total=sum(x.file_size for x in members)
   compressed=sum(max(x.compress_size,1) for x in members)
   if total>1024*1024*1024: return False,"ZIP descompactado ultrapassa o limite de segurança."
   if total>50*1024*1024 and total/compressed>100: return False,"ZIP bloqueado por taxa de compactação anormal."
   for x in members:
    p=Path(x.filename)
    if p.is_absolute() or ".." in p.parts: return False,"ZIP contém caminho de arquivo inseguro."
  return True,""
 except zipfile.BadZipFile:
  return False,"Arquivo ZIP inválido ou corrompido."
 finally:
  fileobj.stream.seek(pos)

def malware_scan(fileobj,name):
 try:
  pos=fileobj.stream.tell(); fileobj.stream.seek(0,2); size=fileobj.stream.tell(); fileobj.stream.seek(pos)
  app.logger.info("malware_scan_upload_bytes=%s",size)
 except Exception:
  pass
 if not MALWARE_SCANNER_URL:
  return ("ERRO","Scanner de malware não configurado.") if MALWARE_SCAN_REQUIRED else ("NAO_VERIFICADO","Scanner ainda não ativado.")
 try:
  fileobj.stream.seek(0)
  headers={"Authorization":"Bearer "+MALWARE_SCANNER_TOKEN} if MALWARE_SCANNER_TOKEN else {}
  response=requests.post(
   MALWARE_SCANNER_URL+"/scan",
   headers=headers,
   files={"file":(name,fileobj.stream,fileobj.mimetype or "application/octet-stream")},
   timeout=(5,150),
  )
  fileobj.stream.seek(0)
  if response.status_code!=200:
   app.logger.error("scanner_http_status=%s",response.status_code)
   return "ERRO","Scanner indisponível."
  data=response.json()
  status=str(data.get("status","ERRO")).upper()
  if status=="LIMPO":
   return "LIMPO",str(data.get("detail","Arquivo verificado."))[:255]
  if status in {"SUSPEITO","INFECTADO"}:
   return status,str(data.get("detail","Ameaça detectada."))[:255]
  app.logger.error("scanner_invalid_response")
  return "ERRO","Resposta inválida do scanner."
 except Exception as exc:
  app.logger.error("scanner_connection_error=%s",type(exc).__name__)
  try:
   fileobj.stream.seek(0)
  except Exception:
   pass
  return "ERRO","Falha ao consultar o scanner de malware."

def csrf_token():
 token=session.get("_csrf_token")
 if not token:
  token=secrets.token_urlsafe(32); session["_csrf_token"]=token
 return token

def csrf_field():
 return f'<input type="hidden" name="_csrf_token" value="{csrf_token()}">'

@app.before_request
def csrf_protect():
 if request.method in {"POST","PUT","PATCH","DELETE"}:
  expected=session.get("_csrf_token","")
  received=request.form.get("_csrf_token","") or request.headers.get("X-CSRF-Token","")
  if not expected or not received or not secrets.compare_digest(expected,received):
   return page("<h1>Solicitação expirada</h1><div class='card'>Atualize a página e tente novamente.</div>","Segurança"),400

@app.after_request
def security_headers(response):
 response.headers["X-Content-Type-Options"]="nosniff"
 response.headers["X-Frame-Options"]="SAMEORIGIN"
 response.headers["Referrer-Policy"]="no-referrer"
 response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
 response.headers["Content-Security-Policy"]="default-src 'self'; img-src 'self' data:; frame-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; connect-src 'self' https://*.r2.cloudflarestorage.com https://challenges.cloudflare.com; form-action 'self'; base-uri 'self'; frame-ancestors 'self'"
 response.headers["Cache-Control"]="no-store"
 if request.is_secure: response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
 return response

@app.errorhandler(404)
def not_found(error):
 return page("<h1>Página não encontrada</h1><div class='card'>O endereço solicitado não existe ou não está mais disponível.</div>","Página não encontrada"),404

@app.errorhandler(500)
def internal_error(error):
 db.session.rollback()
 return page("<h1>Não foi possível concluir</h1><div class='card'>Ocorreu um erro interno. Tente novamente. Se o problema persistir, entre em contato com o suporte da MALIBUB.</div>","Erro interno"),500

@app.errorhandler(413)
def too_large(error):
 return page("<h1>Arquivo muito grande</h1><div class='card'>O envio ultrapassou o limite permitido. Divida o exame em arquivos menores antes de reenviar.</div>","Arquivo muito grande"),413

@app.cli.command("cleanup-expired-files")
def cleanup_expired_files_command():
 result=purge_expired_exam_files()
 print(f"retention_cleanup examined={result['examined']} deleted={result['deleted']} failed={result['failed']}")

@app.route("/health")
def health():
 try:
  db.session.execute(db.text("SELECT 1"))
  storage="enabled" if object_storage_enabled() else "local"
  return {"status":"ok","database":"ok","storage":storage},200
 except Exception:
  return {"status":"error","database":"unavailable"},503

@app.route("/health/security")
def health_security():
 if session.get("role")!="Radiologista": return {"status":"not_found"},404
 scanner_configured=bool(MALWARE_SCANNER_URL and MALWARE_SCANNER_TOKEN)
 scanner_ok=False
 if scanner_configured:
  try:
   r=requests.get(MALWARE_SCANNER_URL+"/health",timeout=(5,20))
   scanner_ok=r.status_code==200 and r.json().get("status")=="ok"
  except Exception: scanner_ok=False
 return {"status":"ok" if scanner_configured and scanner_ok and MALWARE_SCAN_REQUIRED else "attention","malware_scan_required":MALWARE_SCAN_REQUIRED,"scanner_configured":scanner_configured,"scanner_reachable":scanner_ok,"storage_private":object_storage_enabled()},200 if scanner_configured and scanner_ok and MALWARE_SCAN_REQUIRED else 503

@app.route("/health/storage")
def health_storage():
 if request.headers.get("X-Health-Check")!="storage": return {"status":"not_found"},404
 if not object_storage_enabled():
  return {"status":"error","storage":"not_configured"},503
 probe=f"health/{uuid.uuid4().hex}.txt"
 try:
  r2_client().put_object(Bucket=R2_BUCKET,Key=probe,Body=b"malibub-storage-check",ContentType="text/plain")
  r2_client().head_object(Bucket=R2_BUCKET,Key=probe)
  body=r2_client().get_object(Bucket=R2_BUCKET,Key=probe)["Body"].read()
  if body!=b"malibub-storage-check": raise RuntimeError("storage probe mismatch")
  r2_client().delete_object(Bucket=R2_BUCKET,Key=probe)
  return {"status":"ok","storage":"read_write_delete"},200
 except Exception:
  try: r2_client().delete_object(Bucket=R2_BUCKET,Key=probe)
  except Exception: pass
  return {"status":"error","storage":"unavailable"},503

@app.route("/assets/<path:filename>")
def assets(filename):
 return send_from_directory(Path(app.root_path)/"assets", filename)

class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(100)); email=db.Column(db.String(120),unique=True); password=db.Column(db.String(255)); role=db.Column(db.String(30)); active=db.Column(db.Boolean,default=True); logo=db.Column(db.String(255)); logo_name=db.Column(db.String(255)); report_model=db.Column(db.String(255)); report_model_name=db.Column(db.String(255)); report_top_mm=db.Column(db.Integer,default=72); report_bottom_mm=db.Column(db.Integer,default=42); privacy_version=db.Column(db.String(20)); privacy_ack_at=db.Column(db.DateTime); failed_login_count=db.Column(db.Integer,default=0,nullable=False); access_locked=db.Column(db.Boolean,default=False,nullable=False)
class ReportModel(db.Model):
 id=db.Column(db.Integer,primary_key=True); clinic_id=db.Column(db.Integer,index=True,nullable=False); name=db.Column(db.String(255)); stored=db.Column(db.String(255)); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class Exam(db.Model):
 id=db.Column(db.Integer,primary_key=True); protocol=db.Column(db.String(30),unique=True); patient=db.Column(db.String(120)); sex=db.Column(db.String(20)); birth=db.Column(db.String(20)); dentist=db.Column(db.String(120)); exam_date=db.Column(db.String(20)); exam_type=db.Column(db.String(100)); observation=db.Column(db.String(500)); priority=db.Column(db.String(20),default="NORMAL"); contracted_amount=db.Column(db.Float); status=db.Column(db.String(50),default="Enviado"); clinic_id=db.Column(db.Integer); due_at=db.Column(db.DateTime); report=db.Column(db.Text,default=""); report_html=db.Column(db.Text,default=""); revision_reason=db.Column(db.Text); revision_requested_at=db.Column(db.DateTime); released_at=db.Column(db.DateTime); signed_by=db.Column(db.String(120)); signed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class ExamFile(db.Model):
 id=db.Column(db.Integer,primary_key=True); exam_id=db.Column(db.Integer); name=db.Column(db.String(255)); stored=db.Column(db.String(255)); kind=db.Column(db.String(30),default="entrada"); uploaded_by=db.Column(db.String(100)); scan_status=db.Column(db.String(20),default="PENDENTE"); scan_detail=db.Column(db.String(255))
class Finance(db.Model):
 id=db.Column(db.Integer,primary_key=True); date=db.Column(db.Date,default=datetime.utcnow().date); description=db.Column(db.String(200)); kind=db.Column(db.String(20)); amount=db.Column(db.Float,default=0)
class ClinicPrice(db.Model):
 id=db.Column(db.Integer,primary_key=True); clinic_id=db.Column(db.Integer,index=True,nullable=False); exam_type=db.Column(db.String(100),nullable=False); amount=db.Column(db.Float,nullable=False); active=db.Column(db.Boolean,default=True); __table_args__=(db.UniqueConstraint("clinic_id","exam_type",name="uq_clinic_exam_price"),)

CSS="""*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#f4f8fa;color:#153847}a{text-decoration:none;color:#087b9b}.shell{display:grid;grid-template-columns:220px 1fr;min-height:100vh}aside{background:linear-gradient(180deg,#06394c,#087b9b);color:white;padding:28px 20px}aside a{color:white;display:block;margin:20px 0}.brand{font-size:25px;font-weight:800}.brand span{display:block;font-weight:400}.brand small{display:block;font-size:10px;margin-top:8px}main{padding:32px;max-width:1500px}.card{background:white;border:1px solid #dce8ec;border-radius:16px;padding:22px;margin-bottom:18px;box-shadow:0 5px 18px #0c40540d}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}input,select,textarea{width:100%;padding:11px;border:1px solid #cbdde3;border-radius:8px;margin-top:6px}label{font-weight:700}button,.btn{display:inline-block;background:#087b9b;color:white;border:0;border-radius:8px;padding:11px 16px;margin:8px 5px 5px 0}.gold{background:#c99b3b}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #e5edef}.badge{background:#e6f4f7;padding:5px 9px;border-radius:12px}.workspace{display:grid;grid-template-columns:1fr 1fr;gap:18px}.viewer{max-height:650px;overflow:auto}.viewer img{width:100%;height:auto;display:block;margin:10px 0 18px;border-radius:8px}.viewer iframe{width:100%;height:560px;border:1px solid #dce8ec;border-radius:8px;margin:10px 0 18px}.exam-file{margin-bottom:18px}.filebar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.filebar b{margin-right:auto}.editor textarea{min-height:430px}.muted{color:#657f89}.notice{padding:12px;background:#fff7df;border-left:4px solid #c99b3b;margin:12px 0}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.cards .card b{display:block;font-size:28px;color:#087b9b}.clinic-cell{display:flex;align-items:center;gap:8px;min-width:130px}.clinic-cell img{width:38px;height:38px;object-fit:contain;border-radius:6px;background:#fff;border:1px solid #e5edef;padding:2px}
.login-approved{min-height:100vh;display:grid;grid-template-columns:52.5% 47.5%;gap:0;background:#020b14;color:white;overflow:hidden}
.login-visual{background-color:#020b14;background-image:url('/assets/login-malibub-aprovado.png');background-repeat:no-repeat;background-position:left top;background-size:191% 100%;position:relative;border:0;outline:0;overflow:hidden;isolation:isolate}
.login-visual:after{content:"";position:absolute;top:0;right:0;width:2px;height:100%;background:#020b14;pointer-events:none;z-index:6}.login-visual .footer-mask{position:absolute;left:0;right:0;bottom:0;height:56px;background:#020b14;z-index:5;pointer-events:none}
.login-copy{position:relative;z-index:1}.login-copy h1{font-size:42px;line-height:1.18;margin:0 0 18px;color:#fff}.login-copy h1 span{color:#20d8ef}.login-copy p{font-size:20px;margin:0;color:#d8e2e8}
.login-panel{display:flex;align-items:center;justify-content:center;background:#020b14;padding:42px;margin:0;border:0;outline:0;position:relative;z-index:7}
.login-card{width:min(540px,100%)}.login-card h2{font-size:30px;margin:0 0 8px}.login-card .sub{color:#9cb0bd;margin:0 0 28px}
.login-card label{display:block;color:#fff;font-size:16px;margin:16px 0 7px}.login-card input{height:56px;margin:0;background:#07131f;border:1px solid #526574;border-radius:10px;color:#fff;font-size:16px;padding:0 48px 0 16px;outline:none}.login-card input:focus{border-color:#20d8ef;box-shadow:0 0 0 2px #20d8ef2e}
.login-card .pass-wrap{position:relative}.login-card .pass-wrap input{width:100%}.login-card .eye{position:absolute;right:8px;bottom:7px;width:42px;height:42px;padding:0;margin:0;background:transparent;color:#c8d3da;border:0;font-size:20px}
.login-card .submit{width:100%;height:56px;margin:20px 0 0;border:0;border-radius:10px;background:linear-gradient(90deg,#14cfe7,#1de4ed);color:#00121c;font-size:18px;font-weight:800}
.login-card .foot{text-align:center;color:#9cb0bd;margin-top:22px;font-size:14px}.login-card .foot b{color:#20d8ef}.login-flash{padding:11px 13px;border:1px solid #d9a441;background:#251d0d;color:#fff;border-radius:8px;margin-bottom:15px}
.login-footer{position:fixed;bottom:12px;left:52.5%;right:0;text-align:center;color:#9fb0bb;font-size:12px;z-index:9;pointer-events:none;background:transparent;padding:0}
@media print{
 @page{size:A4 portrait;margin:12mm}
 body{background:#fff!important;color:#153847!important}
 .shell{display:block!important;min-height:auto!important}
 aside{display:none!important}
 main{padding:0!important;margin:0!important;max-width:none!important;overflow:visible!important}
 .print-result .card{border:0!important;box-shadow:none!important;border-radius:0!important;padding:0!important;margin:0!important}
 .print-result .no-print{display:none!important}
 .print-result h1{margin-top:0!important}
 .print-result{width:100%!important}
 .print-result .badge{border:1px solid #dce8ec!important}
 .viewer.no-print{display:none!important}
}
@media(max-width:900px){.login-approved{grid-template-columns:1fr}.login-visual{min-height:42vh;padding:28px 8%;background-size:191% 100%}.login-copy h1{font-size:30px}.login-copy p{font-size:16px}.login-panel{padding:38px 22px 70px}.login-footer{left:0;font-size:10px}.shell,.workspace,.grid,.cards{grid-template-columns:1fr}.shell aside{position:relative}main{padding:18px;max-width:100%;overflow:hidden}.card{padding:16px}table{display:block;overflow-x:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}.viewer{max-height:70vh}.viewer iframe{height:60vh}.editor textarea{min-height:300px}.filebar .btn{padding:9px 12px}}@media(max-width:520px){.login-visual{min-height:34vh}.login-panel{padding:28px 16px 64px}.login-card h2{font-size:25px}.login-card input,.login-card .submit{height:52px}aside{padding:20px 16px}aside a{display:inline-block;margin:12px 14px 4px 0}.brand{font-size:22px}main{padding:14px}.card{border-radius:12px;padding:14px}button,.btn{max-width:100%}.workspace{gap:10px}}"""

PRIVACY_VERSION="1.0-2026-10-07"
PRIVACY_TEXT="""<h1>Política de Privacidade</h1>
<div class="card"><p><b>Versão 1.0 — 07/10/2026</b></p>
<p>A Radiologia MALIBUB respeita a privacidade e a proteção dos dados pessoais. No fluxo de prestação de serviços de radiologia, a clínica contratante atua como Controladora das decisões essenciais sobre os dados de seus pacientes e a Radiologia MALIBUB atua como Operadora, tratando os dados em nome da clínica e conforme suas instruções, sem prejuízo da análise do papel aplicável a cada operação concreta.</p>
<p>Podem ser tratados dados de identificação, informações relacionadas ao exame, imagens radiológicas, informações clínicas pertinentes, laudos e registros técnicos necessários à segurança e à execução do serviço. Dados de saúde são dados pessoais sensíveis e recebem proteção reforçada.</p>
<p>A MALIBUB adota medidas técnicas e administrativas destinadas a reduzir riscos de acesso não autorizado, perda, alteração, divulgação ou tratamento inadequado, incluindo autenticação, segregação de acesso, comunicação HTTPS, armazenamento privado e controles de segurança e retenção.</p>
<p>Os dados de pacientes não são utilizados pela MALIBUB para publicidade ou mala direta. Solicitações relacionadas aos dados do paciente devem ser dirigidas prioritariamente à clínica responsável pelo atendimento. Para assuntos de privacidade relacionados à operação da MALIBUB: <b>radiologiamalibub@gmail.com</b>.</p>
<p><b>Operadora:</b> Radiologia MALIBUB — CNPJ 39.853.728/0001-00 — Avenida Sete de Setembro, 3000 - CONJ 206 ANDAR 01, Condomínio Lifespace, CEP 80.230-085, Centro, Curitiba - PR.</p>
<p>Os arquivos de exames armazenados na área operacional da plataforma estão sujeitos à política técnica de exclusão automática após 90 dias, ressalvados prazos legais, regulatórios ou instruções formalmente aplicáveis. Outros registros podem possuir prazos de retenção distintos.</p>
<p>Esta Política poderá ser atualizada para refletir alterações legais, regulatórias ou operacionais. Alterações relevantes poderão exigir nova ciência na plataforma.</p></div>"""

TERMS_TEXT="""<h1>Termos de Uso e Proteção de Dados</h1>
<div class="card"><p><b>Versão 1.0 — 07/10/2026</b></p>
<p>A plataforma MALIBUB destina-se ao envio, processamento e disponibilização de exames e laudos radiológicos por usuários autorizados.</p>
<p>A clínica contratante declara que é responsável pelas decisões essenciais sobre os dados pessoais que encaminha à plataforma, pela legitimidade do tratamento e pela autorização para encaminhar os dados e arquivos necessários à execução do serviço. A Radiologia MALIBUB trata esses dados em nome da clínica e conforme suas instruções no fluxo clínico contratado.</p>
<p>Credenciais de acesso são individuais e devem ser protegidas. O usuário não deve compartilhar senha ou permitir acesso por pessoa não autorizada.</p>
<p>É proibido utilizar a plataforma para finalidade incompatível com a prestação do serviço, inserir conteúdo ilícito ou tentar contornar os controles de segurança.</p>
<p>Ao enviar um exame, a clínica confirma que está autorizada a encaminhar os dados e arquivos necessários à execução do serviço solicitado.</p>
<p>Contato de privacidade da Radiologia MALIBUB: <b>radiologiamalibub@gmail.com</b>.</p></div>"""

@app.route("/privacidade")
def privacy_policy():
 return page(PRIVACY_TEXT,"Política de Privacidade · MALIBUB")

@app.route("/termos")
def terms_of_use():
 return page(TERMS_TEXT,"Termos de Uso · MALIBUB")

@app.route("/privacidade/ciencia",methods=["GET","POST"])
def privacy_acknowledgement():
 if session.get("role")!="Clinica" or not session.get("uid"): return redirect("/")
 u=User.query.get_or_404(session["uid"])
 if request.method=="POST":
  if request.form.get("ack")!="yes":
   flash("Para continuar, confirme a ciência da Política de Privacidade e dos Termos de Uso.")
   return redirect("/privacidade/ciencia")
  u.privacy_version=PRIVACY_VERSION; u.privacy_ack_at=datetime.utcnow(); db.session.commit()
  flash("Ciência de privacidade registrada.")
  return redirect("/dashboard")
 body=f"""<h1>Proteção de Dados e LGPD</h1><div class='card'><p>A Clínica declara estar ciente de que atua como Controladora dos dados pessoais encaminhados à plataforma e que a Radiologia MALIBUB atua como Operadora no tratamento realizado para execução dos serviços contratados, conforme a Política de Privacidade e os Termos de Uso.</p><p><a href='/privacidade' target='_blank'>Ler Política de Privacidade</a> · <a href='/termos' target='_blank'>Ler Termos de Uso</a></p><form method='post'>{csrf_field()}<label style='display:flex;gap:10px;align-items:flex-start'><input type='checkbox' name='ack' value='yes' required style='width:auto;margin-top:3px'> <span>Li e estou ciente da Política de Privacidade e dos Termos de Uso — versão {PRIVACY_VERSION}.</span></label><button class='gold' type='submit'>Continuar</button></form></div>"""
 return page(body,"Ciência de Privacidade · MALIBUB")

def page(body,title="MALIBUB"):
 msgs="".join(f'<div class="notice">{html_escape(m)}</div>' for m in __import__("flask").get_flashed_messages())
 body=msgs+body
 nav=""
 if session.get("uid"):
  nav=f'''<aside><div class="brand">MALIBUB<span>Imaginologia</span><small>PRECISÃO • CONFIANÇA • AGILIDADE</small></div><a href="/dashboard">Painel</a>{'<a href="/new">Novo Exame</a>' if session.get('role')=='Clinica' else ''}{'<a href="/finance">Financeiro</a><a href="/admin/usuarios">Administração</a>' if session.get('role')=='Radiologista' else ''}<a href="/minha-conta">Minha conta</a><form method="post" action="/logout" style="margin:0">{csrf_field()}<button type="submit" style="width:100%;text-align:left;background:none;border:0;color:inherit;padding:12px 14px;cursor:pointer;font:inherit">Sair</button></form></aside>'''
  return f'<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{CSS}</style><div class="shell">{nav}<main>{body}</main></div></html>'
 return f'<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{CSS}</style>{body}</html>'

_initialized=False
_last_purge_ts=0.0
@app.before_request
def require_current_privacy_ack():
 if not _initialized: return
 if session.get("role")=="Clinica" and session.get("uid") and request.endpoint not in {"privacy_acknowledgement","privacy_policy","terms_of_use","logout","assets","static"}:
  u=db.session.get(User,session["uid"])
  if u and u.privacy_version!=PRIVACY_VERSION:
   return redirect("/privacidade/ciencia")

@app.before_request
def init():
 global _initialized
 if _initialized: return
 db.create_all()
 if db.engine.dialect.name=="postgresql":
  try:
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS privacy_version VARCHAR(20)"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS privacy_ack_at TIMESTAMP"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS access_locked BOOLEAN NOT NULL DEFAULT FALSE"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS logo VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS logo_name VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE exam_file ADD COLUMN IF NOT EXISTS scan_status VARCHAR(20) DEFAULT 'PENDENTE'"))
   db.session.execute(db.text("ALTER TABLE exam_file ADD COLUMN IF NOT EXISTS scan_detail VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'NORMAL'"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS contracted_amount DOUBLE PRECISION"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS report_html TEXT"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS revision_reason TEXT"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS revision_requested_at TIMESTAMP"))
   db.session.execute(db.text("UPDATE \"user\" SET active=TRUE WHERE active IS NULL"))
   db.session.commit()
  except Exception:
   db.session.rollback()
 if db.engine.dialect.name=="sqlite":
  try:
   cols=[r[1] for r in db.session.execute(db.text("PRAGMA table_info(exam)")).fetchall()]
   if "signed_by" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN signed_by VARCHAR(120)"))
   if "signed_at" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN signed_at DATETIME"))
   if "report_html" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN report_html TEXT"))
   if "revision_reason" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN revision_reason TEXT"))
   if "revision_requested_at" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN revision_requested_at DATETIME"))
   db.session.commit()
  except Exception:
   db.session.rollback()
 # Nunca cria contas com senha conhecida em produção.
 # Bootstrap de demonstração é permitido somente fora de produção e exige senha fornecida por variável de ambiente.
 demo_password=os.getenv("BOOTSTRAP_DEMO_PASSWORD","")
 if APP_ENV!="production" and os.getenv("BOOTSTRAP_DEMO_USERS","false").lower()=="true" and demo_password and len(demo_password)>=12 and not User.query.first():
  db.session.add(User(name="Clínica Demo",email="clinica@malibub.com",password=generate_password_hash(demo_password),role="Clinica"))
  db.session.add(User(name="Dra. Marina",email="radiologista@malibub.com",password=generate_password_hash(demo_password),role="Radiologista"))
  db.session.commit()
 _initialized=True
 global _last_purge_ts
 now_ts=time.time()
 if now_ts-_last_purge_ts >= AUTO_PURGE_INTERVAL_SECONDS:
  _last_purge_ts=now_ts
  try:
   purge_expired_exam_files()
  except Exception as exc:
   db.session.rollback()
   app.logger.error("retention_cleanup_failed error_type=%s",type(exc).__name__)

LOGIN_ATTEMPTS=defaultdict(deque)
LOGIN_LIMIT=5
LOGIN_WINDOW=15*60

def login_client_key():
 forwarded=request.headers.get("X-Forwarded-For","")
 ip=(forwarded.split(",")[0].strip() if forwarded else request.remote_addr) or "unknown"
 return ip[:64]

def login_rate_limited(key):
 now=time.monotonic(); attempts=LOGIN_ATTEMPTS[key]
 while attempts and now-attempts[0]>LOGIN_WINDOW: attempts.popleft()
 return len(attempts)>=LOGIN_LIMIT

def record_login_failure(key):
 LOGIN_ATTEMPTS[key].append(time.monotonic())

def clear_login_failures(key):
 LOGIN_ATTEMPTS.pop(key,None)

@app.route("/",methods=["GET","POST"])
def login():
 if request.method=="GET" and session.get("uid"):
  session.clear(); session["_csrf_token"]=secrets.token_urlsafe(32)
 if request.method=="POST":
  client_key=login_client_key()
  if login_rate_limited(client_key):
   flash("Muitas tentativas de acesso. Aguarde alguns minutos e tente novamente.")
   return redirect("/")
  email=request.form.get("email","").strip().lower()[:120]
  password=request.form.get("password","")[:256]
  u=User.query.filter_by(email=email).first()
  if u and u.role=="Clinica" and u.access_locked:
   flash("CONTATE A MALIBUB PELO WHATSAPP.")
   return redirect("/")
  if u and u.active is not False and password and check_password_hash(u.password,password):
   if u.role=="Clinica":
    u.failed_login_count=0
    db.session.commit()
   clear_login_failures(client_key)
   session.clear(); session.permanent=True
   session.update(uid=u.id,role=u.role,name=u.name,_csrf_token=secrets.token_urlsafe(32)); return redirect("/dashboard")
  record_login_failure(client_key)
  if u and u.role=="Clinica" and u.active is not False:
   u.failed_login_count=(u.failed_login_count or 0)+1
   if u.failed_login_count>=3:
    u.access_locked=True
    db.session.commit()
    flash("CONTATE A MALIBUB PELO WHATSAPP.")
    return redirect("/")
   db.session.commit()
  flash("E-mail ou senha inválidos.")
 msgs="".join(f'<div class="login-flash">{html_escape(m)}</div>' for m in __import__("flask").get_flashed_messages())
 body=f'''<div class="login-approved">
 <section class="login-visual" aria-label="MALIBUB Imaginologia Odontológica"><span class="footer-mask" aria-hidden="true"></span></section>
 <section class="login-panel"><div class="login-card">{msgs}<h2>Acesse sua conta</h2><p class="sub">Entre para enviar ou acessar seus exames.</p>
 <form method="post" autocomplete="off">{csrf_field()}<label for="email">Email</label><input id="email" type="email" name="email" value="" placeholder="voce@clinica.com" required autocomplete="off" autocapitalize="none" spellcheck="false">
 <div class="pass-wrap"><label for="pwd">Senha</label><input id="pwd" type="password" name="password" value="" placeholder="Sua senha" required autocomplete="new-password"><button class="eye" type="button" aria-label="Mostrar ou ocultar senha" onclick="var p=document.getElementById('pwd');p.type=p.type==='password'?'text':'password';this.textContent=p.type==='password'?'◉':'○'">◉</button></div>
 <button class="submit" type="submit">Entrar</button></form><div class="foot">Acesso exclusivo para clínicas e radiologista.<br><a href="/privacidade" target="_blank">Política de Privacidade</a> · <a href="/termos" target="_blank">Termos de Uso</a></div></div></section>
<div class="login-footer">© 2026 Malibub Radiologia &nbsp; Todos os Direitos Reservados</div></div>'''
 return page(body,"Entrar · MALIBUB")

@app.route("/admin/usuarios",methods=["GET","POST"])
def admin_users():
 if session.get("role")!="Radiologista": return redirect("/")
 if request.method=="POST":
  name=request.form.get("name","").strip()[:100]
  email=request.form.get("email","").strip().lower()[:120]
  password=request.form.get("password","")[:256]
  if not name or not email or len(password)<10:
   flash("Informe nome, e-mail e senha inicial com pelo menos 10 caracteres.")
   return redirect("/admin/usuarios")
  if User.query.filter_by(email=email).first():
   flash("Este e-mail já está cadastrado.")
   return redirect("/admin/usuarios")
  db.session.add(User(name=name,email=email,password=generate_password_hash(password),role="Clinica",active=True))
  db.session.commit()
  flash("Clínica cadastrada com acesso ativo.")
  return redirect("/admin/usuarios")
 clinics=User.query.filter_by(role="Clinica").order_by(User.name).all()
 rows="".join(f"<tr><td>{html_escape(u.name)}</td><td>{html_escape(u.email)}</td><td>{'Bloqueado' if u.access_locked else ('Ativo' if u.active is not False else 'Inativo')}</td><td><a class='btn' href='/admin/usuarios/{u.id}/editar'>Editar</a> <a class='btn' href='/admin/usuarios/{u.id}/precos'>Preços</a> <form method='post' action='/admin/usuarios/{u.id}/desbloquear' style='display:inline-block;margin:0'>{csrf_field()}<button type='submit' {'disabled' if not u.access_locked else ''}>Desbloquear</button></form> <form method='post' action='/admin/usuarios/{u.id}/status' style='display:inline-block;margin:0'>{csrf_field()}<button type='submit'>{'Desativar' if u.active is not False else 'Ativar'}</button></form></td></tr>" for u in clinics)
 body=f"""<h1>Administração</h1><div class='card'><h2>Cadastrar clínica</h2><form method='post'>{csrf_field()}<label>Nome da clínica<input name='name' maxlength='100' required></label><label>E-mail de acesso<input type='email' name='email' maxlength='120' required></label><label>Senha inicial<input type='password' name='password' minlength='10' maxlength='256' required></label><button class='gold' type='submit'>Criar acesso</button></form></div><div class='card'><h2>Clínicas cadastradas</h2><table><tr><th>Clínica</th><th>E-mail</th><th>Status</th><th>Ação</th></tr>{rows or '<tr><td colspan=4>Nenhuma clínica cadastrada.</td></tr>'}</table></div>"""
 return page(body)

@app.route("/admin/usuarios/<int:uid>/editar",methods=["GET","POST"])
def admin_user_edit(uid):
 if session.get("role")!="Radiologista": return redirect("/")
 u=User.query.get_or_404(uid)
 if u.role!="Clinica": return redirect("/admin/usuarios")
 if request.method=="POST":
  name=request.form.get("name","").strip()[:100]
  email=request.form.get("email","").strip().lower()[:120]
  password=request.form.get("password","")[:256]
  if not name or not email:
   flash("Nome e e-mail são obrigatórios."); return redirect(url_for("admin_user_edit",uid=u.id))
  if User.query.filter(User.email==email,User.id!=u.id).first():
   flash("Este e-mail já está cadastrado."); return redirect(url_for("admin_user_edit",uid=u.id))
  if password and len(password)<10:
   flash("A nova senha deve ter pelo menos 10 caracteres."); return redirect(url_for("admin_user_edit",uid=u.id))
  u.name=name; u.email=email
  if password: u.password=generate_password_hash(password)
  db.session.commit(); flash("Cadastro da clínica atualizado."); return redirect("/admin/usuarios")
 body=f"""<h1>Editar clínica</h1><div class='card'><form method='post'>{csrf_field()}<label>Nome da clínica<input name='name' maxlength='100' value='{html_escape(u.name)}' required></label><label>E-mail de acesso<input type='email' name='email' maxlength='120' value='{html_escape(u.email)}' required></label><label>Nova senha (opcional)<input type='password' name='password' minlength='10' maxlength='256'></label><button class='gold' type='submit'>Salvar alterações</button></form></div>"""
 return page(body)

@app.route("/admin/usuarios/<int:uid>/precos",methods=["GET","POST"])
def admin_clinic_prices(uid):
 if session.get("role")!="Radiologista": return redirect("/")
 u=User.query.get_or_404(uid)
 if u.role!="Clinica": return redirect("/admin/usuarios")
 if request.method=="POST":
  exam_type=request.form.get("exam_type","").strip()[:100]
  try:
   amount=float(request.form.get("amount","").strip())
   if amount<=0: raise ValueError
  except (TypeError,ValueError):
   flash("Informe um valor maior que R$ 0,00."); return redirect(url_for("admin_clinic_prices",uid=u.id))
  if not exam_type:
   flash("Informe o tipo de exame."); return redirect(url_for("admin_clinic_prices",uid=u.id))
  item=ClinicPrice.query.filter_by(clinic_id=u.id,exam_type=exam_type).first()
  if item: item.amount=amount; item.active=True
  else: db.session.add(ClinicPrice(clinic_id=u.id,exam_type=exam_type,amount=amount,active=True))
  db.session.commit(); flash("Preço da clínica salvo."); return redirect(url_for("admin_clinic_prices",uid=u.id))
 prices=ClinicPrice.query.filter_by(clinic_id=u.id).order_by(ClinicPrice.exam_type).all()
 rows="".join("<tr><td>"+str(html_escape(x.exam_type))+"</td><td>R$ "+format(x.amount,".2f")+"</td><td><a class='btn' href='/admin/usuarios/"+str(u.id)+"/precos/"+str(x.id)+"/editar'>Editar</a> <form method='post' action='/admin/usuarios/"+str(u.id)+"/precos/"+str(x.id)+"/excluir' style='display:inline-block;margin:0' onsubmit=\"return confirm('Excluir este preço contratado?')\">"+csrf_field()+"<button type='submit'>Excluir</button></form></td></tr>" for x in prices)
 body=f"""<h1>Tabela de preços — {html_escape(u.name)}</h1><div class='card'><p class='muted'>Cadastre o valor contratado por tipo de exame. O sistema usará este preço automaticamente ao laudar.</p><form method='post'>{csrf_field()}<label>Tipo de exame<input name='exam_type' maxlength='100' placeholder='Ex.: Panorâmica' required></label><label>Valor contratado (R$)<input type='number' name='amount' min='0.01' step='0.01' required></label><button class='gold' type='submit'>Salvar preço</button></form></div><div class='card'><h2>Preços cadastrados</h2><table><tr><th>Tipo de exame</th><th>Valor</th><th>Ação</th></tr>{rows or '<tr><td colspan=3>Nenhum preço cadastrado.</td></tr>'}</table></div>"""
 return page(body)

@app.route("/admin/usuarios/<int:uid>/precos/<int:pid>/editar",methods=["GET","POST"])
def admin_clinic_price_edit(uid,pid):
 if session.get("role")!="Radiologista": return redirect("/")
 u=User.query.get_or_404(uid)
 if u.role!="Clinica": return redirect("/admin/usuarios")
 item=ClinicPrice.query.filter_by(id=pid,clinic_id=u.id).first_or_404()
 if request.method=="POST":
  exam_type=request.form.get("exam_type","").strip()[:100]
  try:
   amount=float(request.form.get("amount","").strip())
   if amount<=0: raise ValueError
  except (TypeError,ValueError):
   flash("Informe um valor maior que R$ 0,00.")
   return redirect(url_for("admin_clinic_price_edit",uid=u.id,pid=item.id))
  if not exam_type:
   flash("Informe o tipo de exame.")
   return redirect(url_for("admin_clinic_price_edit",uid=u.id,pid=item.id))
  duplicate=ClinicPrice.query.filter(ClinicPrice.clinic_id==u.id,ClinicPrice.exam_type==exam_type,ClinicPrice.id!=item.id).first()
  if duplicate:
   flash("Já existe um preço cadastrado para este tipo de exame.")
   return redirect(url_for("admin_clinic_price_edit",uid=u.id,pid=item.id))
  item.exam_type=exam_type; item.amount=amount; item.active=True
  db.session.commit(); flash("Preço contratado atualizado.")
  return redirect(url_for("admin_clinic_prices",uid=u.id))
 body=f"""<h1>Editar preço — {html_escape(u.name)}</h1><div class='card'><form method='post'>{csrf_field()}<label>Tipo de exame<input name='exam_type' maxlength='100' value='{html_escape(item.exam_type)}' required></label><label>Valor contratado (R$)<input type='number' name='amount' min='0.01' step='0.01' value='{item.amount:.2f}' required></label><button class='gold' type='submit'>Salvar alterações</button><a class='btn' href='{url_for("admin_clinic_prices",uid=u.id)}'>Cancelar</a></form></div>"""
 return page(body)

@app.route("/admin/usuarios/<int:uid>/precos/<int:pid>/excluir",methods=["POST"])
def admin_clinic_price_delete(uid,pid):
 if session.get("role")!="Radiologista": return redirect("/")
 u=User.query.get_or_404(uid)
 if u.role!="Clinica": return redirect("/admin/usuarios")
 item=ClinicPrice.query.filter_by(id=pid,clinic_id=u.id).first_or_404()
 db.session.delete(item); db.session.commit()
 flash("Preço contratado excluído.")
 return redirect(url_for("admin_clinic_prices",uid=u.id))

@app.route("/admin/usuarios/<int:uid>/status",methods=["POST"])
def admin_user_status(uid):
 if session.get("role")!="Radiologista": return redirect("/")
 u=User.query.get_or_404(uid)
 if u.role!="Clinica":
  flash("Somente acessos de clínicas podem ser alterados aqui.")
  return redirect("/admin/usuarios")
 u.active=not (u.active is not False)
 db.session.commit()
 flash("Acesso da clínica ativado." if u.active else "Acesso da clínica desativado.")
 return redirect("/admin/usuarios")

@app.route("/admin/usuarios/<int:uid>/desbloquear",methods=["POST"])
def admin_unlock_clinic(uid):
 if session.get("role")!="Radiologista": return redirect("/")
 u=User.query.get_or_404(uid)
 if u.role!="Clinica": return redirect("/admin/usuarios")
 u.access_locked=False
 u.failed_login_count=0
 db.session.commit()
 flash("Acesso da clínica desbloqueado.")
 return redirect("/admin/usuarios")

@app.route("/dashboard")
def dashboard():
 if not session.get("uid"): return redirect("/")
 q=Exam.query
 is_radiologist=session["role"]=="Radiologista"
 if not is_radiologist:
  exams=q.filter_by(clinic_id=session["uid"]).order_by(Exam.created_at.desc()).all()
 else:
  exams=q.all()
  def pending_sort_key(e):
   # Primeiro o prazo real de entrega; URG desempata antes dos normais.
   due=e.due_at or datetime.max
   return (due,0 if (e.priority or "NORMAL")=="URG" else 1,e.created_at or datetime.max)
  pending_exams=sorted([e for e in exams if e.status!="Liberado"],key=pending_sort_key)
  completed_exams=sorted([e for e in exams if e.status=="Liberado"],key=lambda e:(e.released_at or e.created_at or datetime.min,e.id or 0),reverse=True)
  exams=pending_exams+completed_exams
 clinics={}
 if is_radiologist:
  clinic_ids=list({e.clinic_id for e in exams if e.clinic_id})
  clinics={u.id:u for u in User.query.filter(User.id.in_(clinic_ids)).all()} if clinic_ids else {}

 headers="<tr><th>Protocolo</th><th>Paciente</th><th>Clínica</th><th>Exame</th><th>Entrega</th><th>Status</th><th>Ação</th></tr>" if is_radiologist else "<tr><th>Protocolo</th><th>Paciente</th><th>Exame</th><th>Entrega</th><th>Status</th><th>Ação</th></tr>"
 colspan=7 if is_radiologist else 6

 def exam_row(e):
  blocked=ExamFile.query.filter(ExamFile.exam_id==e.id,ExamFile.scan_status.in_(["SUSPEITO","INFECTADO"])).first()
  if session["role"]=="Clinica" and blocked:
   action="<span style='display:inline-block;background:#b42318;color:white;font-weight:800;padding:9px 12px;border-radius:8px'>SUSPEITO/INFECTADO</span>"
  else:
   primary_action=(f'<a class="btn" href="/report/{e.id}">Laudar</a>' if is_radiologist and e.status!="Liberado" else (f'<a class="btn" href="/result/{e.id}">Resultado</a>' if e.status=="Liberado" else ""))
   delete_action=(f'<form method="post" action="/exam/{e.id}/excluir" style="display:inline" onsubmit="return confirm(\'Excluir definitivamente este exame, seus arquivos e o lançamento financeiro vinculado? Esta ação não pode ser desfeita.\')">{csrf_field()}<button type="submit" style="background:#b42318">Excluir</button></form>' if is_radiologist else "")
   review_action=(f'<a class="btn" style="margin-left:6px;background:#fff;color:#b97700;border:1px solid #d69c27" href="#revisao" data-exam-id="{e.id}" data-protocol="{html_escape(e.protocol)}" data-patient="{html_escape(e.patient)}" onclick="openRevisionDialog(this);return false">Revisão</a>' if not is_radiologist and e.status=="Liberado" else "")
   replace_action=(f'<a class="btn" style="margin-left:6px" href="/report/{e.id}/laudo-final">Substituir PDF final</a>' if is_radiologist and e.status=="Liberado" else "")
   action=primary_action+review_action+replace_action+delete_action
  delivery=("<b style='color:#b42318'>URG</b><br>" if (e.priority or "NORMAL")=="URG" else "")+due_date_label(e.due_at,e.priority or "NORMAL")
  if is_radiologist:
   clinic=clinics.get(e.clinic_id)
   if clinic and clinic.logo:
    clinic_cell=f"<div class='clinic-cell'><img src='/clinic-logo/{clinic.id}' alt='' loading='lazy'><span>{html_escape(clinic.name)}</span></div>"
   else:
    clinic_cell=html_escape(clinic.name if clinic else "Clínica não identificada")
   return f"<tr><td>{html_escape(e.protocol)}</td><td>{html_escape(e.patient)}</td><td>{clinic_cell}</td><td>{html_escape(e.exam_type)}</td><td>{delivery}</td><td><span class='badge'>{html_escape(e.status)}</span></td><td>{action}</td></tr>"
  return f"<tr><td>{html_escape(e.protocol)}</td><td>{html_escape(e.patient)}</td><td>{html_escape(e.exam_type)}</td><td>{delivery}</td><td><span class='badge'>{html_escape(e.status)}</span></td><td>{action}</td></tr>"

 if is_radiologist:
  pending_rows="".join(exam_row(e) for e in pending_exams)
  completed_rows="".join(exam_row(e) for e in completed_exams)
  body=f'''<h1>Painel da Radiologista</h1><p>Olá, {html_escape(session["name"])}.</p>
  <div class="card"><h2>Exames a fazer</h2><p style="color:#60747d">Ordenados pela prioridade de entrega: os prazos mais próximos aparecem primeiro.</p><table>{headers}{pending_rows or f'<tr><td colspan={colspan}>Nenhum exame pendente.</td></tr>'}</table></div>
  <div class="card" style="margin-top:24px"><h2>Exames já realizados</h2><table>{headers}{completed_rows or f'<tr><td colspan={colspan}>Nenhum exame realizado.</td></tr>'}</table></div>'''
 else:
  rows="".join(exam_row(e) for e in exams)
  body=f'''<h1>Painel da Clínica</h1><p>Olá, {html_escape(session["name"])}.</p><a class="btn gold" href="/new">+ Novo Exame</a><a class="btn" href="/modelo-laudo">Modelo de laudo</a><div class="card"><h2>Exames</h2><table>{headers}{rows or f'<tr><td colspan={colspan}>Nenhum exame.</td></tr>'}</table></div>'''
 if not is_radiologist:
  body+='''<dialog id="revision-dialog" style="width:min(94vw,560px);border:1px solid #cbd5dc;border-radius:12px;padding:24px;box-shadow:0 15px 45px #0003"><h2>Solicitar revisão</h2><p id="revision-exam-label"></p><p>Explique se a correção é no laudo, no template ou em ambos.</p><form id="revision-form" method="post">''' + csrf_field() + '''<label for="revision-reason">Motivo da devolução (obrigatório)</label><textarea id="revision-reason" name="revision_reason" minlength="10" maxlength="2000" rows="6" required style="width:100%" placeholder="Descreva o que precisa ser corrigido"></textarea><div style="display:flex;gap:10px;margin-top:12px"><button type="submit">Enviar para revisão</button><button type="button" onclick="document.getElementById('revision-dialog').close()">Cancelar</button></div></form></dialog><script>
function openRevisionDialog(el){
 const dlg=document.getElementById('revision-dialog');
 document.getElementById('revision-exam-label').textContent='Protocolo: '+el.dataset.protocol+' — Paciente: '+el.dataset.patient;
 document.getElementById('revision-form').action='/exam/'+encodeURIComponent(el.dataset.examId)+'/revisao';
 document.getElementById('revision-reason').value='';
 dlg.showModal();
 document.getElementById('revision-reason').focus();
}
</script>'''
 return page(body)

@app.post("/exam/<int:eid>/excluir")
def delete_exam(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 files=ExamFile.query.filter_by(exam_id=e.id).all()
 stored_keys=[item.stored for item in files if item.stored]
 protocol=e.protocol
 try:
  Finance.query.filter_by(description=f"Laudo {protocol}").delete(synchronize_session=False)
  for item in files: db.session.delete(item)
  db.session.delete(e)
  db.session.commit()
 except Exception as exc:
  db.session.rollback()
  app.logger.error("exam_delete_failed exam_id=%s error_type=%s",eid,type(exc).__name__)
  flash("Não foi possível excluir o exame. Tente novamente.")
  return redirect("/dashboard")
 storage_failures=0
 for key in stored_keys:
  try: storage_delete(key)
  except Exception as exc:
   storage_failures+=1
   app.logger.error("exam_file_storage_delete_failed exam_id=%s error_type=%s",eid,type(exc).__name__)
 if storage_failures:
  flash("Exame excluído do painel. Alguns arquivos não puderam ser removidos do armazenamento e serão tratados pela rotina de retenção.")
 else:
  flash("Exame, arquivos e lançamento financeiro vinculado excluídos.")
 return redirect("/dashboard")

@app.route("/clinic-logo/<int:uid>")
def clinic_logo(uid):
 if not session.get("uid"): return redirect("/")
 if session.get("role")=="Clinica" and session.get("uid")!=uid: return ("",403)
 if session.get("role") not in {"Clinica","Radiologista"}: return ("",403)
 u=User.query.get_or_404(uid)
 if u.role!="Clinica" or not u.logo or not storage_exists(u.logo): return ("",404)
 return storage_response(u.logo,u.logo_name,False)

@app.route("/modelo-laudo",methods=["GET","POST"])
def report_model():
 if session.get("role")!="Clinica": return redirect("/dashboard")
 u=User.query.get_or_404(session["uid"])
 if request.method=="POST":
  try:
   u.report_top_mm=max(20,min(120,int(request.form.get("report_top_mm",u.report_top_mm or 72))))
   u.report_bottom_mm=max(15,min(100,int(request.form.get("report_bottom_mm",u.report_bottom_mm or 42))))
  except Exception: pass
  logo=request.files.get("logo")
  if logo and logo.filename:
   logo_name=secure_filename(logo.filename); logo_ext=Path(logo_name).suffix.lower()
   if logo_ext not in {".jpg",".jpeg",".png"}:
    flash("A logomarca deve estar em JPG ou PNG."); return redirect("/modelo-laudo")
   scan_status,scan_detail=malware_scan(logo,logo_name)
   if scan_status in {"SUSPEITO","INFECTADO"}:
    flash("SUSPEITO/INFECTADO — a logomarca foi bloqueada e não foi armazenada."); return redirect("/modelo-laudo")
   if scan_status=="ERRO" and MALWARE_SCAN_REQUIRED:
    flash("A varredura de segurança está indisponível. O arquivo não foi armazenado."); return redirect("/modelo-laudo")
   stored="logo_"+str(u.id)+"_"+uuid.uuid4().hex+logo_ext; store_upload(logo,stored,logo.mimetype)
   old_logo=u.logo; u.logo=stored; u.logo_name=logo_name; db.session.commit()
   if old_logo:
    try: storage_delete(old_logo)
    except Exception: pass
   flash("Logomarca da clínica atualizada após varredura de segurança.")
  file=request.files.get("report_model")
  if file and file.filename:
   name=secure_filename(file.filename); ext=Path(name).suffix.lower()
   if ext not in {".pdf",".docx",".jpg",".jpeg",".png"}: flash("Use PDF, DOCX, JPG ou PNG."); return redirect("/modelo-laudo")
   scan_status,scan_detail=malware_scan(file,name)
   if scan_status in {"SUSPEITO","INFECTADO"}:
    flash("SUSPEITO/INFECTADO — o modelo de laudo foi bloqueado e não foi armazenado."); return redirect("/modelo-laudo")
   if scan_status=="ERRO" and MALWARE_SCAN_REQUIRED:
    flash("A varredura de segurança está indisponível. O arquivo não foi armazenado."); return redirect("/modelo-laudo")
   stored="modelo_"+str(u.id)+"_"+uuid.uuid4().hex+ext; store_upload(file,stored,file.mimetype)
   item=ReportModel(clinic_id=u.id,name=name,stored=stored); db.session.add(item)
   if not u.report_model:
    u.report_model=stored; u.report_model_name=name
   db.session.commit(); flash("Novo modelo de laudo anexado.")
  else: db.session.commit()
  return redirect("/modelo-laudo")
 models=ReportModel.query.filter_by(clinic_id=u.id).order_by(ReportModel.created_at.desc()).all()
 if u.report_model and not any(x.stored==u.report_model for x in models):
  legacy=ReportModel(clinic_id=u.id,name=u.report_model_name or "Modelo atual",stored=u.report_model); db.session.add(legacy); db.session.commit(); models.insert(0,legacy)
 rows=""
 for m in models:
  active=(m.stored==u.report_model)
  rows+=f"<tr><td>{html_escape(m.name)}</td><td>{'<span class=badge>Em uso</span>' if active else ''}</td><td><a class='btn' href='/modelo-laudo/arquivo?model={m.id}' target='_blank'>Visualizar</a>{'' if active else f'<form method=post action=/modelo-laudo/{m.id}/usar style=display:inline>{csrf_field()}<button type=submit>Usar este modelo</button></form>'}<form method=post action=/modelo-laudo/{m.id}/excluir style=display:inline onsubmit=\"return confirm('Excluir este modelo de laudo?')\">{csrf_field()}<button type=submit style='background:#b42318'>Excluir</button></form></td></tr>"
 models_html=f"<table><tr><th>Modelo</th><th>Status</th><th>Ação</th></tr>{rows}</table>" if rows else "<div class='notice'>Nenhum modelo cadastrado.</div>"
 body=f"""<h1>Identidade visual / Modelos de laudo</h1><div class='card'><p>Cadastre a identidade visual da clínica e mantenha vários modelos de laudo. O modelo marcado como <b>Em uso</b> será aplicado aos novos laudos.</p>{("<p><b>Logomarca atual:</b> "+html_escape(u.logo_name or "")+"</p>") if u.logo else "<div class='notice'>Nenhuma logomarca cadastrada.</div>"}<h3>Modelos cadastrados</h3>{models_html}<hr><form method='post' enctype='multipart/form-data'>{csrf_field()}<label>Trocar logomarca da clínica (JPG ou PNG)<input type='file' name='logo' accept='.jpg,.jpeg,.png,image/jpeg,image/png'></label><label>Anexar outro modelo (PDF, DOCX, JPG ou PNG)<input type='file' name='report_model' accept='.pdf,.docx,.jpg,.jpeg,.png,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,image/jpeg,image/png'></label><div class='grid'><label>Margem superior do conteúdo (mm)<input type='number' name='report_top_mm' min='20' max='120' value='{u.report_top_mm or 72}'></label><label>Margem inferior (mm)<input type='number' name='report_bottom_mm' min='15' max='100' value='{u.report_bottom_mm or 42}'></label></div><p class='muted'>Ajuste estes valores quando o papel timbrado tiver cabeçalho ou rodapé maiores.</p><button class='gold' type='submit'>Salvar / anexar modelo</button></form></div>"""
 return page(body)

@app.post("/modelo-laudo/<int:mid>/usar")
def use_report_model(mid):
 if session.get("role")!="Clinica": return redirect("/dashboard")
 u=User.query.get_or_404(session["uid"]); item=ReportModel.query.filter_by(id=mid,clinic_id=u.id).first_or_404()
 u.report_model=item.stored; u.report_model_name=item.name; db.session.commit(); flash("Modelo de laudo selecionado.")
 return redirect("/modelo-laudo")

@app.post("/modelo-laudo/<int:mid>/excluir")
def delete_report_model(mid):
 if session.get("role")!="Clinica": return redirect("/dashboard")
 u=User.query.get_or_404(session["uid"]); item=ReportModel.query.filter_by(id=mid,clinic_id=u.id).first_or_404()
 was_active=(u.report_model==item.stored); stored=item.stored
 db.session.delete(item)
 if was_active:
  replacement=ReportModel.query.filter(ReportModel.clinic_id==u.id,ReportModel.id!=item.id).order_by(ReportModel.created_at.desc()).first()
  u.report_model=replacement.stored if replacement else None; u.report_model_name=replacement.name if replacement else None
 db.session.commit()
 try: storage_delete(stored)
 except Exception: pass
 flash("Modelo excluído."+(" Outro modelo foi selecionado automaticamente." if was_active and u.report_model else ""))
 return redirect("/modelo-laudo")

@app.route("/modelo-laudo/arquivo")
def report_model_file():
 if not session.get("uid"): return redirect("/")
 uid=session.get("uid")
 if session.get("role")=="Radiologista":
  eid=request.args.get("exam",type=int)
  if not eid: return redirect("/dashboard")
  e=Exam.query.get_or_404(eid); uid=e.clinic_id
 elif session.get("role")!="Clinica": return redirect("/")
 u=User.query.get_or_404(uid); stored=u.report_model; name=u.report_model_name
 mid=request.args.get("model",type=int)
 if mid and session.get("role")=="Clinica":
  item=ReportModel.query.filter_by(id=mid,clinic_id=u.id).first_or_404(); stored=item.stored; name=item.name
 if not stored: return redirect("/dashboard")
 if not storage_exists(stored):
  flash("O modelo de laudo não está disponível no armazenamento atual."); return redirect("/modelo-laudo" if session.get("role")=="Clinica" else "/dashboard")
 return storage_response(stored,name,False)

@app.post("/new/verify-human")
def verify_human_for_upload():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 if not TURNSTILE_SECRET_KEY: return {"proof":""},200
 data=request.get_json(silent=True) or {}
 if not verify_turnstile(data.get("turnstile_token","")): return {"error":"human_verification_failed"},403
 proof=secrets.token_urlsafe(32)
 session["turnstile_proof"]=proof
 session["turnstile_proof_uid"]=session["uid"]
 session["turnstile_proof_at"]=int(time.time())
 return {"proof":proof},200

@app.post("/new/direct-upload-url")
def direct_upload_url():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 if not object_storage_enabled(): return {"error":"storage_unavailable"},503
 data=request.get_json(silent=True) or {}
 if TURNSTILE_SECRET_KEY:
  proof=str(data.get("turnstile_proof",""))
  if not proof or session.get("turnstile_proof")!=proof or session.get("turnstile_proof_uid")!=session.get("uid") or not (0<=int(time.time())-int(session.get("turnstile_proof_at") or 0)<=1800):
   return {"error":"human_verification_required"},403
 name=secure_filename(str(data.get("name","")))
 content_type=str(data.get("content_type") or "application/octet-stream")[:120]
 if not name or Path(name).suffix.lower() not in {".jpg",".jpeg",".png",".pdf",".dcm",".zip",".rar"}: return {"error":"invalid_file"},400
 upload_kind=str(data.get("kind","exam")).strip().lower()
 if upload_kind not in {"exam","request"}: return {"error":"invalid_kind"},400
 if upload_kind=="request" and Path(name).suffix.lower() not in {".jpg",".jpeg",".png",".pdf"}: return {"error":"invalid_request_file"},400
 key="exames/"+uuid.uuid4().hex+"_"+name
 grant=DIRECT_UPLOAD_SIGNER.dumps({"key":key,"name":name,"kind":upload_kind,"uid":session["uid"]})
 url=r2_client().generate_presigned_url("put_object",Params={"Bucket":R2_BUCKET,"Key":key,"ContentType":content_type},ExpiresIn=900)
 app.logger.warning("DIRECT_UPLOAD_URL_OK")
 return {"key":key,"url":url,"content_type":content_type,"grant":grant},200

def verify_direct_upload_grant(item,expected_kind):
 key=str(item.get("key","")); name=secure_filename(str(item.get("name",""))); token=str(item.get("grant",""))
 if not key or not name or not token: raise ValueError("missing upload grant")
 try:
  grant=DIRECT_UPLOAD_SIGNER.loads(token,max_age=1800)
 except (BadSignature,SignatureExpired) as exc:
  raise ValueError("invalid upload grant") from exc
 if grant.get("key")!=key or grant.get("name")!=name or grant.get("kind")!=expected_kind or grant.get("uid")!=session.get("uid"):
  raise ValueError("upload grant mismatch")
 if expected_kind=="request" and Path(name).suffix.lower() not in {".jpg",".jpeg",".png",".pdf"}:
  raise ValueError("invalid request file")
 metadata=r2_client().head_object(Bucket=R2_BUCKET,Key=key)
 size=int(metadata.get("ContentLength",0))
 if size<=0: raise ValueError("empty upload")
 return key,name

@app.post("/new/direct-finalize")
def direct_upload_finalize():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 data=request.get_json(silent=True) or {}; files=data.get("files") or []; request_files=data.get("request_files") or []
 if TURNSTILE_SECRET_KEY:
  proof=str(data.get("turnstile_proof",""))
  if not proof or session.get("turnstile_proof")!=proof or session.get("turnstile_proof_uid")!=session.get("uid") or not (0<=int(time.time())-int(session.get("turnstile_proof_at") or 0)<=1800):
   return {"error":"human_verification_failed"},403
  session.pop("turnstile_proof",None)
  session.pop("turnstile_proof_uid",None)
  session.pop("turnstile_proof_at",None)
 patient=str(data.get("patient","")).strip()[:120]; dentist=str(data.get("dentist","")).strip()[:120]; exam_type=str(data.get("exam_type","")).strip()[:80]; priority=str(data.get("priority","NORMAL")).strip().upper()
 if not files or not request_files or not patient or not dentist or not exam_type: return {"error":"required_fields"},400
 price=ClinicPrice.query.filter_by(clinic_id=session["uid"],exam_type=exam_type,active=True).first()
 if not price: return {"error":"invalid_exam_type"},400
 if priority not in {"NORMAL","URG"}: return {"error":"invalid_priority"},400
 try:
  verified=[verify_direct_upload_grant(item,"exam") for item in files]
  verified_requests=[verify_direct_upload_grant(item,"request") for item in request_files]
  e=Exam(protocol="MB"+datetime.now().strftime("%y%m%d%H%M%S"),patient=patient,sex=str(data.get("sex","Não informado")).strip(),birth=str(data.get("birth",""))[:20],dentist=dentist,exam_date=str(data.get("exam_date",""))[:20],exam_type=exam_type,observation=str(data.get("observation","")).strip()[:500],priority=priority,contracted_amount=round(price.amount*(1.5 if priority=="URG" else 1.0),2),clinic_id=session["uid"],status="Aguardando laudo",due_at=(datetime.utcnow()+timedelta(hours=24) if priority=="URG" else add_business_days_utc(datetime.utcnow(),2)))
  db.session.add(e); db.session.flush()
  for key,name in verified: db.session.add(ExamFile(exam_id=e.id,name=name,stored=key,scan_status="NAO_VERIFICADO",scan_detail="Verificação antivírus opcional pela radiologista."))
  for request_key,request_name in verified_requests:
   db.session.add(ExamFile(exam_id=e.id,name=request_name,stored=request_key,kind="requisicao",scan_status="NAO_VERIFICADO",scan_detail="Requisição/pedido do dentista."))
  db.session.commit()
  session.pop("_pending_direct_uploads",None)
  app.logger.warning("DIRECT_UPLOAD_FINALIZE_OK file_count=%s request_count=%s",len(verified),len(verified_requests))
  return {"status":"ok","redirect":"/dashboard"},200
 except Exception as exc:
  db.session.rollback(); app.logger.error("direct_upload_finalize_failed error_type=%s",type(exc).__name__); return {"error":"finalize_failed"},500

@app.route("/new",methods=["GET","POST"])
def new():
 if session.get("role")!="Clinica": return redirect("/dashboard")
 allowed_ext={".jpg",".jpeg",".png",".pdf",".dcm",".zip",".rar"}
 if request.method=="POST":
  if TURNSTILE_SECRET_KEY and not verify_turnstile(request.form.get("cf-turnstile-response","")):
   flash("Não foi possível confirmar a verificação de segurança. Tente novamente.")
   return redirect("/new")
  incoming=[f for f in request.files.getlist("files") if f and f.filename]
  dentist_requests=[f for f in request.files.getlist("dentist_request") if f and f.filename]
  if not incoming:
   flash("Anexe ao menos um arquivo do exame antes de enviar.")
   return redirect("/new")
  if not dentist_requests:
   flash("Anexe ao menos um arquivo da requisição/pedido do dentista antes de enviar.")
   return redirect("/new")
  request_names=[secure_filename(f.filename) for f in dentist_requests]
  if any((not name or Path(name).suffix.lower() not in {".jpg",".jpeg",".png",".pdf"}) for name in request_names):
   flash("A requisição do dentista deve estar em PDF, JPG, JPEG ou PNG.")
   return redirect("/new")
  invalid=[secure_filename(f.filename) for f in incoming if Path(secure_filename(f.filename)).suffix.lower() not in allowed_ext]
  empty_names=[f.filename for f in incoming if not secure_filename(f.filename)]
  if empty_names:
   flash("Nome de arquivo inválido. Renomeie o arquivo e tente novamente.")
   return redirect("/new")
  if invalid:
   flash("Formato não permitido: "+", ".join(invalid)+". Use JPG, JPEG, PNG, PDF, DCM, ZIP ou RAR.")
   return redirect("/new")
  for f in incoming:
   name=secure_filename(f.filename)
   if Path(name).suffix.lower()==".zip":
    ok,message=validate_zip_upload(f)
    if not ok:
     flash(message)
     return redirect("/new")
  patient=request.form.get("patient","").strip()[:120]
  dentist=request.form.get("dentist","").strip()[:120]
  sex=request.form.get("sex","Não informado").strip()
  exam_type=request.form.get("exam_type","").strip()[:80]
  priority=request.form.get("priority","NORMAL").strip().upper()
  if not patient or not dentist or not exam_type:
   flash("Preencha os dados obrigatórios do exame.")
   return redirect("/new")
  price=ClinicPrice.query.filter_by(clinic_id=session["uid"],exam_type=exam_type,active=True).first()
  if not price:
   flash("Selecione um tipo de exame cadastrado para esta clínica.")
   return redirect("/new")
  if priority not in {"NORMAL","URG"}:
   flash("Selecione um prazo válido.")
   return redirect("/new")
  e=Exam(protocol="MB"+datetime.now().strftime("%y%m%d%H%M%S"),patient=patient,sex=sex,birth=request.form.get("birth",""),dentist=dentist,exam_date=request.form.get("exam_date",""),exam_type=exam_type,observation=request.form.get("observation","").strip()[:500],priority=priority,contracted_amount=round(price.amount*(1.5 if priority=="URG" else 1.0),2),clinic_id=session["uid"],status="Aguardando laudo",due_at=(datetime.utcnow()+timedelta(hours=24) if priority=="URG" else add_business_days_utc(datetime.utcnow(),2)))
  db.session.add(e); db.session.flush()
  uploaded=[]
  try:
   for f in incoming:
    name=secure_filename(f.filename)
    scan_status,scan_detail="NAO_VERIFICADO","Varredura antivírus desativada no fluxo de upload."
    stored="exames/"+uuid.uuid4().hex+"_"+name
    store_upload(f,stored,f.mimetype)
    uploaded.append(stored)
    db.session.add(ExamFile(exam_id=e.id,name=name,stored=stored,scan_status=scan_status,scan_detail=scan_detail))
   for dentist_request,request_name in zip(dentist_requests,request_names):
    request_stored="exames/"+uuid.uuid4().hex+"_"+request_name
    store_upload(dentist_request,request_stored,dentist_request.mimetype)
    uploaded.append(request_stored)
    db.session.add(ExamFile(exam_id=e.id,name=request_name,stored=request_stored,kind="requisicao",scan_status="NAO_VERIFICADO",scan_detail="Requisição/pedido do dentista."))
   db.session.commit()
  except Exception as exc:
   app.logger.error("clinic_exam_upload_failed error_type=%s", type(exc).__name__)
   db.session.rollback()
   for stored in uploaded:
    try: storage_delete(stored)
    except Exception: pass
   flash("Não foi possível concluir o envio. Nenhum exame incompleto foi criado; tente novamente.")
   return redirect("/new")
  return redirect("/dashboard")
 clinic_exam_types=ClinicPrice.query.filter_by(clinic_id=session["uid"],active=True).order_by(ClinicPrice.exam_type.asc()).all()
 exam_type_options="".join(f"<option value='{html_escape(x.exam_type)}'>{html_escape(x.exam_type)}</option>" for x in clinic_exam_types)
 if not exam_type_options:
  exam_type_options="<option value='' disabled selected>Nenhum exame cadastrado para esta clínica</option>"
 turnstile_widget=(f'<div class="cf-turnstile" data-sitekey="{html_escape(TURNSTILE_SITE_KEY)}" data-theme="light"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' if TURNSTILE_SITE_KEY else "")
 body=f'''<h1>Novo Exame</h1><div class="card"><form id="exam-form" method="post" enctype="multipart/form-data">{csrf_field()}<div class="grid"><label>Nome do paciente<input name="patient" required></label><label>Sexo<select name="sex"><option>Feminino</option><option>Masculino</option><option>Não informado</option></select></label><label>Data de nascimento<input type="date" name="birth" required></label><label>Dentista solicitante<input name="dentist" required></label><label>Data do exame<input type="date" name="exam_date" required></label><div class="grid"><label>Tipo de exame<select name="exam_type" required>{exam_type_options}</select></label><label>Prazo<select name="priority" required><option value="NORMAL">Normal — até 2 dias úteis</option><option value="URG">URG — até 24h (+50% do valor do exame)</option></select></label></div></div><label>Observação / motivo <span class="muted">(Avaliação de Maxila/Mandíbula, Exodontia dos 38 e 48, Implante na região do dente XX, ATM etc.)</span><textarea name="observation" maxlength="500"></textarea></label>
<div class="card" style="margin-top:18px"><h3>Requisição / pedido do dentista <span style="color:#b42318">*</span></h3><p class="muted">Obrigatório para enviar o exame. Se o pedido tiver mais de uma página, selecione todos os arquivos. Formatos: PDF, JPG ou PNG.</p><input id="dentist-request" type="file" name="dentist_request" multiple accept=".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png" style="display:none"><div style="display:flex;gap:10px;flex-wrap:wrap"><button type="button" class="blue" id="pick-request">Selecionar arquivos</button><button type="button" class="blue" id="pick-request-more">Adicionar mais arquivos</button></div><div id="request-status" class="notice" style="display:none;margin-top:10px"></div><div id="request-list" style="margin-top:10px"></div></div>
<div class="card" style="margin-top:18px"><h3>Arquivos do exame</h3><p class="muted">Adicione imagens, DICOM, PDF, ZIP ou RAR. Você pode combinar vários arquivos no mesmo exame.</p>
<input id="exam-files" type="file" multiple accept=".jpg,.jpeg,.png,.pdf,.dcm,.zip,.rar" style="display:none">
<input id="exam-folder" type="file" multiple webkitdirectory directory style="display:none">
<div style="display:flex;gap:10px;flex-wrap:wrap"><button type="button" class="blue" id="pick-files">Selecionar arquivos</button><button type="button" class="blue" id="pick-folder">Selecionar pasta</button><button type="button" class="blue" id="pick-more">Adicionar mais arquivos</button></div>
<div id="file-summary" class="notice" style="display:none;margin-top:12px"></div><div id="file-list" style="margin-top:10px"></div></div>
<div id="upload-progress" class="notice" style="display:none"></div><p class="muted" style="margin-top:14px">Ao enviar, a Clínica confirma que está autorizada a encaminhar os dados e arquivos necessários à execução do serviço solicitado.</p>{turnstile_widget}<button id="send-exam" class="gold">Enviar exame</button></form></div>
<script>
(function(){{
 const form=document.getElementById("exam-form"), requestInput=document.getElementById("dentist-request"), requestStatus=document.getElementById("request-status"), input=document.getElementById("exam-files"), folder=document.getElementById("exam-folder"), list=document.getElementById("file-list"), summary=document.getElementById("file-summary"), box=document.getElementById("upload-progress"), btn=document.getElementById("send-exam");
 if(!form||!input) return;
 const csrf=form.querySelector("[name=_csrf_token]").value, selected=[], selectedRequests=[];
 const allowed=/[.](jpg|jpeg|png|pdf|dcm|zip|rar)$/i;
 function fmt(n){{if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";if(n<1073741824)return (n/1048576).toFixed(1)+" MB";return (n/1073741824).toFixed(2)+" GB";}}
 function add(files){{Array.from(files).forEach(file=>{{if(!allowed.test(file.name))return;const rel=file.webkitRelativePath||file.name,key=rel+"|"+file.size+"|"+file.lastModified;if(!selected.some(x=>x.key===key))selected.push({{key:key,file:file,relativePath:rel}});}});render();}}
 function renderRequests(){{requestStatus.style.display=selectedRequests.length?"block":"none";requestStatus.textContent=selectedRequests.length+" arquivo(s) da requisição selecionado(s)";const rl=document.getElementById("request-list");rl.innerHTML="";selectedRequests.forEach((file,i)=>{{const row=document.createElement("div");row.style.cssText="display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #e5e7eb";const name=document.createElement("span");name.textContent=file.name+" — "+fmt(file.size);const rm=document.createElement("button");rm.type="button";rm.className="blue";rm.textContent="Remover";rm.onclick=()=>{{selectedRequests.splice(i,1);renderRequests();}};row.append(name,rm);rl.appendChild(row);}});}}
 function addRequests(files){{Array.from(files).forEach(file=>{{if(!/[.](pdf|jpg|jpeg|png)$/i.test(file.name))return;const key=file.name+"|"+file.size+"|"+file.lastModified;if(!selectedRequests.some(x=>x._key===key)){{file._key=key;selectedRequests.push(file);}}}});renderRequests();}}
 document.getElementById("pick-request").onclick=()=>requestInput.click();document.getElementById("pick-request-more").onclick=()=>requestInput.click();requestInput.onchange=()=>{{addRequests(requestInput.files);requestInput.value="";}};
 function render(){{const total=selected.reduce((s,x)=>s+x.file.size,0);summary.style.display=selected.length?"block":"none";summary.textContent=selected.length+" arquivo(s) selecionado(s) • "+fmt(total);list.innerHTML="";selected.forEach((x,i)=>{{const row=document.createElement("div");row.style.cssText="display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #e5e7eb";const name=document.createElement("span");name.textContent=(x.relativePath||x.file.name)+" — "+fmt(x.file.size);const rm=document.createElement("button");rm.type="button";rm.className="blue";rm.textContent="Remover";rm.onclick=()=>{{selected.splice(i,1);render();}};row.append(name,rm);list.appendChild(row);}});}}
 document.getElementById("pick-files").onclick=()=>input.click();document.getElementById("pick-more").onclick=()=>input.click();document.getElementById("pick-folder").onclick=()=>folder.click();
 input.onchange=()=>{{add(input.files);input.value="";}};folder.onchange=()=>{{add(folder.files);folder.value="";}};
 form.addEventListener("submit",async function(ev){{
  if(!selectedRequests.length){{ev.preventDefault();requestStatus.style.display="block";requestStatus.textContent="Anexe ao menos um arquivo da requisição/pedido do dentista para continuar.";return;}}
  if(!window.fetch||!selected.length){{if(!selected.length){{ev.preventDefault();box.style.display="block";box.textContent="Adicione ao menos um arquivo do exame.";}}return;}}
  ev.preventDefault();btn.disabled=true;box.style.display="block";
  try{{
   let humanProof="";
   const turnstileToken=new FormData(form).get("cf-turnstile-response")||"";
   const verification=await fetch("/new/verify-human",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify({{turnstile_token:turnstileToken}})}});
   if(!verification.ok)throw new Error("human_verification_failed");
   humanProof=(await verification.json()).proof||"";
   const requestFiles=[];
   requestStatus.style.display="block";
   for(let ri=0;ri<selectedRequests.length;ri++){{
    const req=selectedRequests[ri];requestStatus.textContent="Enviando requisição "+(ri+1)+" de "+selectedRequests.length+"...";
    const ra=await fetch("/new/direct-upload-url",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify({{name:req.name,content_type:req.type||"application/octet-stream",kind:"request",turnstile_proof:humanProof}})}});if(!ra.ok)throw new Error("request_auth");const rs=await ra.json();
    const rp=await fetch(rs.url,{{method:"PUT",headers:{{"Content-Type":rs.content_type}},body:req}});if(!rp.ok)throw new Error("request_put");requestFiles.push({{key:rs.key,name:req.name,grant:rs.grant}});
   }}
   requestStatus.textContent=selectedRequests.length+" arquivo(s) da requisição enviado(s).";
   const uploaded=[];
   for(let i=0;i<selected.length;i++){{
    const file=selected[i].file;box.textContent="Enviando arquivo "+(i+1)+" de "+selected.length+" • "+fmt(file.size);
    const a=await fetch("/new/direct-upload-url",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify({{name:file.name,content_type:file.type||"application/octet-stream",kind:"exam",turnstile_proof:humanProof}})}});if(!a.ok)throw new Error("auth");const s=await a.json();
    const p=await fetch(s.url,{{method:"PUT",headers:{{"Content-Type":s.content_type}},body:file}});if(!p.ok)throw new Error("put");uploaded.push({{key:s.key,name:file.name,grant:s.grant}});
   }}
   box.textContent="Finalizando envio...";const fd=new FormData(form),payload={{files:uploaded,request_files:requestFiles,turnstile_proof:humanProof}};["patient","sex","birth","dentist","exam_date","exam_type","priority","observation"].forEach(k=>payload[k]=fd.get(k)||"");
   const d=await fetch("/new/direct-finalize",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify(payload)}});if(!d.ok)throw new Error("finalize");const r=await d.json();location.href=r.redirect||"/dashboard";
  }}catch(e){{box.textContent="O envio direto não pôde ser concluído. Tente novamente.";btn.disabled=false;}}
 }});
}})();
</script>'''
 return page(body)

@app.post("/exam-file/<int:fid>/scan")
def scan_exam_file(fid):
 if session.get("role")!="Radiologista": return redirect("/")
 f=ExamFile.query.get_or_404(fid); e=Exam.query.get_or_404(f.exam_id)
 if not f.stored or not storage_exists(f.stored):
  flash("Arquivo não encontrado no armazenamento privado.")
  return redirect(url_for("report",eid=e.id))
 if not object_storage_enabled():
  flash("Verificação manual exige armazenamento privado ativo.")
  return redirect(url_for("report",eid=e.id))
 try:
  private_url=r2_client().generate_presigned_url("get_object",Params={"Bucket":R2_BUCKET,"Key":f.stored},ExpiresIn=900)
  headers={"Authorization":"Bearer "+MALWARE_SCANNER_TOKEN} if MALWARE_SCANNER_TOKEN else {}
  response=requests.post(MALWARE_SCANNER_URL+"/scan-url",headers=headers,json={"url":private_url},timeout=(5,620))
  if response.status_code!=200:
   f.scan_status="ERRO"; f.scan_detail="Não foi possível concluir a verificação."; db.session.commit()
   flash("Não foi possível concluir a verificação antivírus.")
   return redirect(url_for("report",eid=e.id))
  data=response.json(); status=str(data.get("status","ERRO")).upper()
  f.scan_status=status if status in {"LIMPO","INFECTADO","SUSPEITO"} else "ERRO"
  f.scan_detail=str(data.get("detail",""))[:255]; db.session.commit()
  flash("Arquivo verificado: "+f.scan_status+".")
 except Exception as exc:
  app.logger.error("manual_scan_error=%s",type(exc).__name__)
  f.scan_status="ERRO"; f.scan_detail="Falha na verificação manual."; db.session.commit()
  flash("Não foi possível concluir a verificação antivírus.")
 return redirect(url_for("report",eid=e.id))

@app.route("/exam-file/<int:fid>")
def exam_file(fid):
 if not session.get("uid"): return redirect("/")
 f=ExamFile.query.get_or_404(fid); e=Exam.query.get_or_404(f.exam_id)
 if session.get("role")=="Clinica" and e.clinic_id!=session.get("uid"): return redirect("/dashboard")
 if session.get("role") not in {"Clinica","Radiologista"}: return redirect("/")
 if f.scan_status in {"SUSPEITO","INFECTADO"} or not f.stored:
  flash("Arquivo bloqueado pela varredura de segurança.")
  return redirect("/dashboard")
 if not storage_exists(f.stored):
  flash("Arquivo não encontrado no armazenamento privado.")
  return redirect("/dashboard")
 return storage_response(f.stored,f.name,request.args.get("download")=="1")

@app.route("/report/<int:eid>/exame-pronto",methods=["POST"])
def upload_ready_exam(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 incoming=[file for file in request.files.getlist("finished_files") if file and file.filename]
 invalid=[secure_filename(file.filename) for file in incoming if Path(secure_filename(file.filename)).suffix.lower() not in {".jpg",".jpeg",".pdf"}]
 empty_names=[file.filename for file in incoming if not secure_filename(file.filename)]
 if not incoming:
  flash("Selecione JPG, JPEG ou PDF.")
  return redirect(url_for("report",eid=e.id))
 if empty_names:
  flash("Nome de arquivo inválido. Renomeie o arquivo e tente novamente.")
  return redirect(url_for("report",eid=e.id))
 if invalid:
  flash("Formato não permitido: "+", ".join(invalid)+". Use JPG, JPEG ou PDF.")
  return redirect(url_for("report",eid=e.id))
 uploaded=[]
 try:
  for file in incoming:
   name=secure_filename(file.filename)
   scan_status,scan_detail=malware_scan(file,name)
   if scan_status in {"SUSPEITO","INFECTADO"}:
    db.session.add(ExamFile(exam_id=e.id,name=name,stored="",kind="bloqueado",uploaded_by=session.get("name"),scan_status=scan_status,scan_detail=scan_detail))
    continue
   if scan_status=="ERRO" and MALWARE_SCAN_REQUIRED:
    raise RuntimeError("malware scanner unavailable")
   ext=Path(name).suffix.lower()
   stored="exames/"+uuid.uuid4().hex+ext
   store_upload(file,stored,file.mimetype)
   uploaded.append(stored)
   db.session.add(ExamFile(exam_id=e.id,name=name,stored=stored,kind="exame_pronto",uploaded_by=session.get("name"),scan_status=scan_status,scan_detail=scan_detail))
  db.session.commit()
 except Exception:
  db.session.rollback()
  for stored in uploaded:
   try: storage_delete(stored)
   except Exception: pass
  flash("Não foi possível anexar o exame pronto. Nenhum arquivo parcial foi mantido; tente novamente.")
  return redirect(url_for("report",eid=e.id))
 blocked_count=len(incoming)-len(uploaded)
 if blocked_count:
  flash(f"{blocked_count} arquivo(s) suspeito(s)/infectado(s) foram bloqueados e não disponibilizados.")
 if uploaded:
  flash(f"{len(uploaded)} arquivo(s) do exame pronto anexado(s) após varredura de segurança.")
 return redirect(url_for("report",eid=e.id))

@app.route("/report/<int:eid>/laudo-final",methods=["GET","POST"])
def approved_final_pdf(eid):
 # Substituição explícita do PDF entregue à clínica, sem refaturar o exame.
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 if e.status!="Liberado":
  flash("Libere o exame antes de substituir o PDF final.")
  return redirect(url_for("report",eid=e.id))
 if request.method=="GET":
  current=ExamFile.query.filter_by(exam_id=e.id,kind="laudo_final").order_by(ExamFile.id.desc()).first()
  body=f"""<section class='card'><h2>Substituir PDF final - {html_escape(e.protocol or '')}</h2>
  <p>Somente a radiologista pode publicar uma nova versão. A substituição não altera os dados clínicos nem gera nova cobrança.</p>
  <p>O arquivo deve estar conferido e assinado pela profissional responsável. A plataforma não assina este PDF automaticamente.</p>
  <p>Versão atual: {html_escape(current.name) if current else 'PDF gerado pela plataforma'}</p>
  <form method='post' enctype='multipart/form-data'>
  {csrf_field()}<label>PDF final aprovado <input type='file' name='final_pdf' accept='application/pdf,.pdf' required></label>
  <label><input type='checkbox' name='approved' value='yes' required> Confirmo que conferi o documento e que a assinatura final foi validada pela radiologista.</label>
  <button type='submit' onclick="return confirm('Publicar este PDF como versão oficial para a clínica?')">Publicar PDF final</button></form></section>"""
  return page(body)
 if request.form.get("approved")!="yes":
  flash("Confirme a conferência e assinatura do documento.")
  return redirect(request.path)
 file=request.files.get("final_pdf")
 if not file or not file.filename or Path(secure_filename(file.filename)).suffix.lower()!=".pdf":
  flash("Selecione um PDF válido.")
  return redirect(request.path)
 name=secure_filename(file.filename)
 status,detail=malware_scan(file,name)
 if status in {"SUSPEITO","INFECTADO"} or (status=="ERRO" and MALWARE_SCAN_REQUIRED):
  flash("Arquivo não aprovado pela verificação de segurança.")
  return redirect(request.path)
 try:
  from pypdf import PdfReader
  file.stream.seek(0)
  reader=PdfReader(file.stream,strict=True)
  if len(reader.pages)<1 or reader.is_encrypted: raise ValueError("invalid PDF")
  file.stream.seek(0)
 except Exception:
  flash("O PDF não pôde ser validado.")
  return redirect(request.path)
 stored="exames/"+uuid.uuid4().hex+".pdf"
 try:
  store_upload(file,stored,"application/pdf")
  current=ExamFile.query.filter_by(exam_id=e.id,kind="laudo_final").all()
  for previous in current:previous.kind="laudo_final_anterior"
  db.session.add(ExamFile(exam_id=e.id,name=name,stored=stored,kind="laudo_final",uploaded_by=session.get("name"),scan_status=status,scan_detail=detail))
  db.session.commit()
 except Exception:
  db.session.rollback()
  try:storage_delete(stored)
  except Exception:pass
  flash("Falha ao publicar o PDF final. O documento anterior foi preservado.")
  return redirect(request.path)
 flash("Nova versão do PDF final publicada, sem cobrança adicional.")
 return redirect("/dashboard")

@app.route("/report/<int:eid>/exame-pronto/<int:fid>/excluir",methods=["POST"])
def delete_ready_exam_file(eid,fid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 item=ExamFile.query.filter_by(id=fid,exam_id=e.id,kind="exame_pronto").first_or_404()
 stored=item.stored
 try:
  if stored: storage_delete(stored)
  db.session.delete(item); db.session.commit()
  flash("Anexo do exame pronto excluído.")
 except Exception as exc:
  db.session.rollback()
  app.logger.error("ready_exam_delete_failed file_id=%s exam_id=%s error_type=%s",item.id,e.id,type(exc).__name__)
  flash("Não foi possível excluir o anexo. Tente novamente.")
 return redirect(url_for("report",eid=e.id))

# Rich text limitado a marcação tipográfica, sem scripts, URLs ou imagens.
def clean_report_html(raw):
 from html.parser import HTMLParser
 from html import escape as esc
 class Cleaner(HTMLParser):
  def __init__(self):
   super().__init__(convert_charrefs=True); self.parts=[]; self.stack=[]
  def handle_starttag(self,tag,attrs):
   allowed={"b","strong","i","em","u","p","div","br","ul","ol","li","font","span"}
   if tag not in allowed: self.stack.append(None); return
   props=dict(attrs); attributes=""
   if tag=="font":
    face=props.get("face","").lower()
    if face in ("arial","times new roman","courier new"): attributes+=' face="'+esc(face,quote=True)+'"'
    size=props.get("size","")
    if size in ("1","2","3","4","5","6","7"): attributes+=' size="'+size+'"'
   if tag in ("p","div"):
    align=props.get("align","").lower()
    if align in ("left","center","right","justify"): attributes+=' align="'+align+'"'
   if tag=="span":
    import re
    style=props.get("style","").lower()
    match=re.search(r"font-size:\s*(\d{1,2})px",style)
    if match and 8<=int(match.group(1))<=30: attributes+=' data-size="'+match.group(1)+'"'
    match=re.search(r"font-family:\s*([^;]+)",style)
    if match and match.group(1).strip(" '\\\"") in ("arial","times new roman","courier new"): attributes+=' data-font="'+esc(match.group(1).strip(" '\\\""),quote=True)+'"'
   self.parts.append("<"+tag+attributes+("/>" if tag=="br" else ">"))
   if tag!="br": self.stack.append(tag)
  def handle_endtag(self,tag):
   if tag in self.stack:
    while self.stack:
     t=self.stack.pop()
     if t: self.parts.append("</"+t+">")
     if t==tag: break
  def handle_data(self,data): self.parts.append(esc(data))
  def result(self):
   while self.stack:
    t=self.stack.pop()
    if t:self.parts.append("</"+t+">")
   return "".join(self.parts)[:100000]
 p=Cleaner(); p.feed((raw or "")[:100000]); return p.result()

def rich_report_blocks(raw_html, plain):
 from html.parser import HTMLParser
 from html import escape as esc
 class Blocks(HTMLParser):
  def __init__(self):
   super().__init__(convert_charrefs=True);self.blocks=[];self.parts=[];self.tags=[];self.align="left";self.list_stack=[];self.counter=0;self.pending_break=False
  def flush(self,force=False):
   # Fecha as tags de formatação antes de enviar cada parágrafo ao ReportLab.
   # Tags abertas podem atravessar <div>, <p> ou <br> no HTML do editor.
   content="".join(self.parts).strip()
   if content or force:
    closing="".join("</"+mapped+">" for _,mapped in reversed(self.tags))
    self.blocks.append(((content+closing) if content else "&nbsp;",self.align))
   self.parts=["<"+mapped+">" for _,mapped in self.tags]
   self.align="left"
  def handle_starttag(self,tag,attrs):
   d=dict(attrs)
   if tag in ("p","div","li"):
    self.flush();self.align=d.get("align","left")
    if tag=="li":
     if self.list_stack and self.list_stack[-1]=="ol":self.counter+=1;self.parts.append(str(self.counter)+". ")
     else:self.parts.append("&#8226; ")
   elif tag in ("ul","ol"):self.flush();self.list_stack.append(tag);self.counter=0
   elif tag=="br":self.flush(force=True)
   elif tag in ("b","strong","i","em","u"):
    mapped={"strong":"b","em":"i"}.get(tag,tag);self.parts.append("<"+mapped+">");self.tags.append((tag,mapped))
   elif tag in ("font","span"):
    face=d.get("face",d.get("data-font","")).lower()
    family={"arial":"Helvetica","times new roman":"Times-Roman","courier new":"Courier"}.get(face)
    size=d.get("data-size","")
    if not size:
     size={"1":"8","2":"9","3":"10","4":"12","5":"15","6":"18","7":"22"}.get(d.get("size",""),"")
    attributes=(" name='"+family+"'" if family else "")+(" size='"+size+"'" if size else "")
    self.parts.append("<font"+attributes+">");self.tags.append((tag,"font"))
  def handle_endtag(self,tag):
   if tag in ("p","div","li"):self.flush(force=True)
   elif tag in ("ul","ol"):
    self.flush()
    if self.list_stack:self.list_stack.pop()
   elif tag in ("b","strong","i","em","u","font","span"):
    if self.tags and self.tags[-1][0]==tag:
     self.parts.append("</"+self.tags.pop()[1]+">")
  def handle_data(self,data):
   # Preserve quebras de linha reais do editor, inclusive linhas vazias.
   # Evita transformar vários parágrafos em um único bloco no PDF.
   lines=data.replace("\r\n","\n").replace("\r","\n").split("\n")
   for index,line in enumerate(lines):
    if index:self.flush(force=True)
    if line:self.parts.append(esc(line))
 p=Blocks()
 if raw_html:
  p.feed(clean_report_html(raw_html));p.flush()
 if not p.blocks:
  p.blocks=[(esc(line) if line else "&nbsp;","left") for line in (plain or "").splitlines()]
 return p.blocks or [("&nbsp;","left")]

@app.post("/exam/<int:eid>/revisao")
def request_exam_revision(eid):
 if session.get("role")!="Clinica": return redirect("/")
 e=Exam.query.filter_by(id=eid,clinic_id=session["uid"]).first_or_404()
 if e.status!="Liberado":
  flash("A revisão só pode ser solicitada para laudos liberados.")
  return redirect("/dashboard")
 reason=request.form.get("revision_reason","").strip()
 if len(reason)<10 or len(reason)>2000:
  flash("Descreva a correção necessária entre 10 e 2000 caracteres.")
  return redirect("/dashboard")
 e.revision_reason=reason
 e.revision_requested_at=datetime.utcnow()
 e.status="Revisão solicitada"
 db.session.commit()
 flash("Revisão enviada à radiologista.")
 return redirect("/dashboard")

@app.route("/report/<int:eid>",methods=["GET","POST"])
def report(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 if ExamFile.query.filter(ExamFile.exam_id==e.id,ExamFile.kind=="bloqueado",ExamFile.scan_status.in_(["SUSPEITO","INFECTADO"]),ExamFile.uploaded_by!=session.get("name")).first():
  flash("Exame bloqueado pela segurança. Arquivo suspeito/infectado não foi disponibilizado.")
  return redirect("/dashboard")
 files=ExamFile.query.filter_by(exam_id=e.id).filter((ExamFile.kind=="entrada") | (ExamFile.kind==None)).all()
 request_files=ExamFile.query.filter_by(exam_id=e.id,kind="requisicao").all()
 ready_files=ExamFile.query.filter_by(exam_id=e.id,kind="exame_pronto").all()
 if request.method=="POST":
  if e.status=="Liberado":
   flash("Este laudo já foi liberado. Nenhuma nova receita foi lançada.")
   return redirect("/dashboard")
  if not ready_files:
   flash("Anexe o exame pronto/template antes de finalizar e liberar.")
   return redirect(url_for("report",eid=e.id))
  report_text=request.form.get("report","").strip()
  if not report_text:
   flash("Digite o laudo antes de finalizar.")
   return redirect(url_for("report",eid=e.id))
  existing_revenue=Finance.query.filter_by(description=f"Laudo {e.protocol}",kind="Entrada").first()
  if e.status=="Revisão solicitada" and existing_revenue:
   amount=existing_revenue.amount
  else:
   try:
    raw_amount=request.form.get("amount","").strip()
    if not raw_amount: raise ValueError
    amount=float(raw_amount)
    if amount <= 0: raise ValueError
   except (TypeError,ValueError):
    flash("Informe o valor do laudo. Para evitar cobrança incorreta, o valor deve ser maior que R$ 0,00.")
    return redirect(url_for("report",eid=e.id))
  e.report=report_text; e.report_html=clean_report_html(request.form.get("report_html","")); e.status="Liberado"; e.revision_reason=None; e.revision_requested_at=None; e.released_at=datetime.utcnow(); e.signed_by=session.get("name") or "Dra. Marina"; e.signed_at=datetime.utcnow()
  db.session.flush()
  check=result_pdf(e.id)
  if getattr(check,"status_code",200) >= 400:
   db.session.rollback()
   flash("PDF final indisponível. O exame não foi liberado nem faturado.")
   return redirect(url_for("report",eid=e.id))
  if not existing_revenue:
   db.session.add(Finance(description=f"Laudo {e.protocol}",kind="Entrada",amount=amount))
  db.session.commit(); return redirect("/dashboard")
 imgs="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><span class='badge'>{html_escape(f.scan_status or 'NAO_VERIFICADO')}</span><form method='post' action='/exam-file/{f.id}/scan' style='display:inline'>{csrf_field()}<button type='submit'>Verificar com antivírus</button></form><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{html_escape(f.name)}'>" if f.name.lower().endswith(('.jpg','.jpeg','.png','.webp')) else (f"<iframe src='/exam-file/{f.id}' title='{html_escape(f.name)}'></iframe>" if f.name.lower().endswith('.pdf') else "<div class='notice'>Pré-visualização indisponível para este formato. Use Abrir ou Baixar.</div>")) + "</div>") for f in files)
 request_html="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{html_escape(f.name)}'>" if f.name.lower().endswith(('.jpg','.jpeg','.png')) else f"<iframe src='/exam-file/{f.id}' title='{html_escape(f.name)}'></iframe>") + "</div>") for f in request_files)
 ready_html="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a><form method='post' action='/report/{e.id}/exame-pronto/{f.id}/excluir' style='display:inline-block;margin:0' onsubmit=\"return confirm('Excluir este anexo individualmente? Esta ação não pode ser desfeita.')\">{csrf_field()}<button type='submit'>Excluir</button></form></div>" + (f"<img src='/exam-file/{f.id}'>" if f.name.lower().endswith(('.jpg','.jpeg')) else f"<iframe src='/exam-file/{f.id}'></iframe>") + "</div>") for f in ready_files)
 clinic=User.query.get(e.clinic_id); price=ClinicPrice.query.filter_by(clinic_id=e.clinic_id,exam_type=e.exam_type,active=True).first(); suggested_amount=(e.contracted_amount if e.contracted_amount is not None else ((price.amount*(1.5 if (e.priority or "NORMAL")=="URG" else 1.0)) if price else None)); model_link=(f"<a class='btn' href='/modelo-laudo/arquivo?exam={e.id}' target='_blank'>Ver modelo de laudo da clínica</a>" if clinic and clinic.report_model else "<span class='muted'>Clínica sem modelo de laudo cadastrado.</span>")
 revision_notice=(f"<div class='card' style='border:2px solid #d69c27;margin-bottom:14px'><h2>Revisão solicitada pela clínica</h2><p style='white-space:pre-wrap'>{html_escape(e.revision_reason or '')}</p></div>" if e.status=="Revisão solicitada" else "")
 body=f'''{revision_notice}<h1>Ambiente da Radiologista — {html_escape(e.protocol)}</h1><div style="margin-bottom:12px">{model_link}</div><div class="card"><h3 style="margin-top:0">Dados do paciente</h3><div class="grid"><div><b>Paciente</b><br>{html_escape(e.patient or '—')}</div><div><b>Sexo</b><br>{html_escape(e.sex or 'Não informado')}</div><div><b>Data de nascimento</b><br>{html_escape(br_date(e.birth) or '—')}</div><div><b>Dentista solicitante</b><br>{html_escape(e.dentist or '—')}</div><div><b>Data do exame</b><br>{html_escape(br_date(e.exam_date) or '—')}</div><div><b>Tipo de exame</b><br>{html_escape(e.exam_type or '—')}</div></div><p style="margin-bottom:0"><b>Prazo:</b> {'URG — até 24h (+50%)' if (e.priority or 'NORMAL')=='URG' else 'Normal — até 2 dias úteis'}<br><b>Observação / motivo:</b> <span class="muted">{html_escape(e.observation or 'Sem observação clínica.')}</span></p></div><div class="workspace"><section class="card viewer"><h2>Requisição / pedido do dentista</h2><p class="muted">Documento(s) enviado(s) pela clínica com a solicitação do profissional.</p>{request_html or '<div class="notice">Nenhuma requisição anexada. Exames anteriores à obrigatoriedade podem não possuir este documento.</div>'}<hr style="margin:24px 0;border:0;border-top:1px solid #dce8ec"><h2>Imagens / arquivos do exame</h2>{imgs or 'Nenhum anexo.'}<hr style="margin:24px 0;border:0;border-top:1px solid #dce8ec"><h2>Exame pronto / Templates</h2><p class="muted">Anexe o exame final produzido pela radiologista em JPG/JPEG e/ou PDF. Os arquivos ficarão vinculados a este exame.</p><form method="post" action="/report/{e.id}/exame-pronto" enctype="multipart/form-data">{csrf_field()}<input type="file" name="finished_files" accept=".jpg,.jpeg,.pdf,image/jpeg,application/pdf" multiple required><button class="gold" type="submit">Anexar exame pronto</button></form>{ready_html or '<div class="notice">Nenhum template/exame pronto anexado ainda.</div>'}</section><section class="card editor"><h2>Laudo escrito</h2><div class="laudo-toolbar" role="toolbar" aria-label="Ferramentas de edição" style="display:flex;flex-direction:column;gap:5px;margin:8px 0 10px;width:100%;min-width:0"><div class="laudo-select-row" style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:6px;width:100%"><select style="width:100%;min-width:0;height:32px;padding:3px 7px;font-size:12px" aria-label="Fonte" onchange="formatReport('fontName',this.value)"><option value="Arial">Arial</option><option value="Times New Roman">Times New Roman</option><option value="Courier New">Courier New</option></select><select style="width:100%;min-width:0;height:32px;padding:3px 7px;font-size:12px" aria-label="Tamanho" onchange="formatReport('fontSize',this.value)"><option value="2">Pequena</option><option value="3" selected>Normal</option><option value="4">Média</option><option value="5">Grande</option></select></div><div class="laudo-actions-row" style="display:flex;flex-wrap:nowrap;align-items:center;gap:3px;width:100%;min-width:0;overflow-x:auto;padding-bottom:2px"><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('bold')" title="Negrito"><b>N</b></button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('italic')" title="Itálico"><i>I</i></button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('underline')" title="Sublinhado"><u>S</u></button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('insertUnorderedList')" title="Marcadores">•</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('insertOrderedList')" title="Numeração">1.</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('justifyLeft')" title="Esquerda">≡</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('justifyCenter')" title="Centro">☰</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('justifyRight')" title="Direita">≡</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('justifyFull')" title="Justificado">▤</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('undo')" title="Desfazer">↶</button><button style="flex:1 0 0;min-width:27px;height:30px;padding:3px 2px;font-size:11px;white-space:nowrap" type="button" onclick="formatReport('redo')" title="Refazer">↷</button></div></div><form method="post">{csrf_field()}<div id="report-rich" contenteditable="true" role="textbox" aria-label="Laudo escrito" aria-multiline="true" style="background:white;border:1px solid #cbdde3;border-radius:7px;min-height:340px;padding:12px;line-height:1.5;overflow:auto;white-space:pre-wrap"></div><textarea name="report" id="report-plain" hidden required>{html_escape(e.report or '')}</textarea><textarea name="report_html" id="report-html" hidden>{html_escape(e.report_html or '')}</textarea><label>Valor do laudo (R$)<input type="number" min="0.01" step="0.01" name="amount" value="{format(suggested_amount,'.2f') if suggested_amount is not None else ''}" placeholder="0,00" required></label><p class="muted">{'Valor contratado desta clínica para este tipo de exame, preenchido automaticamente.' if suggested_amount is not None else 'Sem preço contratado para este tipo de exame. Informe o valor antes de liberar.'} O valor será usado no Financeiro e no relatório de cobrança da clínica.</p><div class="editor-actions"><button type="button" onclick="localStorage.setItem('malibub_draft_{e.id}',document.querySelector('[name=report]').value);this.textContent='Rascunho salvo ✓'">Salvar rascunho</button><button type="submit" formaction="/report/{e.id}/preview-pdf" formmethod="post" formtarget="_blank">Visualizar laudo</button><button class="gold" type="submit">Finalizar e liberar</button></div></form><script>(function(){{const rich=document.getElementById('report-rich'),plain=document.getElementById('report-plain'),key='malibub_draft_{e.id}';const htmlField=document.getElementById('report-html');const saved=plain.value||localStorage.getItem(key)||'';if(htmlField.value){{rich.innerHTML=htmlField.value;}}else{{rich.textContent=saved;}}function sync(){{plain.value=rich.innerText.replace(/\\u00a0/g,' ').replace(/\\r\\n/g,'\\n');htmlField.value=rich.innerHTML;}}rich.addEventListener('input',sync);document.querySelectorAll('.editor form').forEach(form=>form.addEventListener('submit',sync));window.formatReport=function(command,value){{rich.focus();document.execCommand(command,false,value||null);sync();}};window.editReport=function(command){{rich.focus();if(command==='undo'||command==='redo'){{document.execCommand(command);sync();return;}}let selection=window.getSelection();if(!selection.rangeCount)return;let str=selection.toString();if(command==='upper')str=str.toUpperCase();else if(command==='lower')str=str.toLowerCase();else if(command==='bullet')str=str.split('\\n').map(x=>'• '+x).join('\\n');else if(command==='number')str=str.split('\\n').map((x,i)=>(i+1)+'. '+x).join('\\n');else if(command==='indent')str=str.split('\\n').map(x=>'    '+x).join('\\n');document.execCommand('insertText',false,str);sync();}};const save=document.querySelector('.editor-actions button[type=button]');if(save)save.onclick=function(){{sync();localStorage.setItem(key,plain.value);this.textContent='Rascunho salvo ✓';}};sync();}})();</script></section></div>'''
 return page(body)

@app.route("/report/<int:eid>/preview-pdf",methods=["POST"])
def preview_report_pdf(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 # Salva somente uma prévia temporária do texto no registro para reutilizar o mesmo gerador.
 old_report=e.report; old_report_html=e.report_html; old_status=e.status; old_signed_by=e.signed_by; old_signed_at=e.signed_at; old_released=e.released_at
 e.report=request.form.get("report","")
 e.report_html=clean_report_html(request.form.get("report_html",""))
 e.status="Liberado"; e.signed_by=session.get("name") or "Dra. Marina"; e.signed_at=datetime.utcnow(); e.released_at=e.signed_at
 db.session.flush()
 try:
  response=result_pdf(eid)
 finally:
  e.report=old_report; e.report_html=old_report_html; e.status=old_status; e.signed_by=old_signed_by; e.signed_at=old_signed_at; e.released_at=old_released
  db.session.rollback()
 if hasattr(response,"headers"):
  response.headers["Content-Disposition"]=f'inline; filename="{e.protocol}_previa.pdf"'
 return response

def br_date(value):
 if not value: return ""
 raw=str(value).strip()
 try: return datetime.strptime(raw,"%Y-%m-%d").strftime("%d/%m/%Y")
 except ValueError: return raw

BRASILIA_TZ=ZoneInfo("America/Sao_Paulo")
def brasilia_datetime(value):
 if not value: return None
 # Datas gravadas historicamente no PostgreSQL são UTC sem timezone.
 if value.tzinfo is None: value=value.replace(tzinfo=timezone.utc)
 return value.astimezone(BRASILIA_TZ)

def brasilia_stamp(value):
 local=brasilia_datetime(value)
 return local.strftime("%d/%m/%Y %H:%M") if local else ""

def add_business_days_utc(value,days=2):
 """Add Monday-Friday business days, preserving the local Brasilia clock time."""
 local=brasilia_datetime(value or datetime.utcnow())
 added=0
 while added<days:
  local+=timedelta(days=1)
  if local.weekday()<5: added+=1
 return local.astimezone(timezone.utc).replace(tzinfo=None)

def due_date_label(value,priority="NORMAL"):
 local=brasilia_datetime(value)
 if not local: return "—"
 return local.strftime("%d/%m/%Y %H:%M") if priority=="URG" else local.strftime("%d/%m/%Y")

@app.route("/result/<int:eid>/pdf")
def result_pdf(eid):
 if not session.get("uid"): return redirect("/")
 if session.get("role") not in {"Clinica","Radiologista"}: return redirect("/")
 e=Exam.query.get_or_404(eid)
 if session.get("role")=="Clinica" and e.clinic_id!=session.get("uid"): return redirect("/dashboard")
 if e.status!="Liberado": return redirect("/dashboard")
 final_file=ExamFile.query.filter_by(exam_id=e.id,kind="laudo_final").order_by(ExamFile.id.desc()).first()
 if final_file and final_file.stored and final_file.scan_status not in {"SUSPEITO","INFECTADO"} and storage_exists(final_file.stored):
  return storage_response(final_file.stored,final_file.name,request.args.get("print")!="1")
 from reportlab.lib.pagesizes import A4
 from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
 from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
 from reportlab.lib import colors
 from reportlab.lib.enums import TA_CENTER
 from reportlab.lib.units import mm
 from xml.sax.saxutils import escape
 buf=io.BytesIO(); clinic=User.query.get(e.clinic_id)
 model_name=(clinic.report_model_name or "").lower() if clinic else ""
 # O gerador TMJ reconstruído é permitido somente quando não há PDF ativo.
 # Se a clínica cadastrou um PDF, preservar o arquivo escolhido no fluxo personalizado.
 is_tmj_model=("laudotmj" in model_name or "tmj" in model_name)
 has_pdf_model=bool(clinic and clinic.report_model and Path(clinic.report_model).suffix.lower()==".pdf")
 # O modelo TMJ é reconstruído como documento fluido: o texto digitado no laudo
 # passa a fazer parte do fluxo do documento, empurrando o conteúdo seguinte e
 # criando novas páginas automaticamente, em vez de ser desenhado por cima do PDF.
 # Assinatura vetorial reutilizável para todos os formatos de laudo.
 signature_paths=["599,10 590,1 574,0 550,12 533,28 523,43 521,56 528,75 539,89 504,118 496,120 493,116 508,82 508,74 499,71 438,118 424,125 422,119 434,96 432,88 424,89 400,110 394,96 381,92 416,55 418,44 413,40 402,42 377,57 334,97 335,87 330,81 324,81 305,90 296,89 363,22 366,15 363,7 348,6 320,30 295,57 284,84 217,146 203,148 200,139 210,106 244,73 265,44 266,33 263,29 255,27 241,40 208,85 199,102 70,209 31,234 0,244 2,255 31,246 68,224 136,171 191,123 193,124 190,147 195,156 203,159 215,158 235,146 287,97 294,101 305,101 320,95 295,150 296,156 303,158 311,151 340,106 372,75 393,60 395,61 356,101 356,107 360,110 379,103 387,105 388,118 348,151 349,161 360,162 373,158 391,141 396,127 411,115 415,133 425,137 450,123 488,93 490,94 483,109 483,120 491,130 504,130 515,124 549,95 577,112 581,118 569,126 544,133 544,143 569,138 589,126 592,113 584,103 556,85 594,35 599,23","587,12 589,19 579,38 549,77 545,78 533,60 534,46 562,17 579,10"]
 def draw_report_signature(cv,page_width,baseline=20*mm):
  cv.saveState()
  try:
   cv.setFillColor(colors.HexColor("#41499A"))
   p=cv.beginPath(); sw=23*mm; sh=sw*256/600; x0=(page_width-sw)/2
   for contour in signature_paths:
    for i,xy in enumerate(contour.split()):
     x,y=map(int,xy.split(",")); px=x0+x*sw/600; py=baseline+(256-y)*sh/256
     if i==0: p.moveTo(px,py)
     else: p.lineTo(px,py)
    p.close()
   cv.drawPath(p,stroke=0,fill=1,fillMode=0)
  finally: cv.restoreState()
 from reportlab.platypus import Flowable, KeepTogether
 class ReportSignature(Flowable):
  def __init__(self):
   super().__init__(); self.width=150*mm; self.height=24*mm; self.hAlign="CENTER"
  def draw(self):
   w=self.width
   draw_report_signature(self.canv,w,baseline=12*mm)
   self.canv.setFillColor(colors.HexColor("#06394C")); self.canv.setFont("Helvetica-Bold",9)
   self.canv.drawCentredString(w/2,8*mm,"Dra. Marina L. Bub")
   self.canv.setFillColor(colors.HexColor("#52666E")); self.canv.setFont("Helvetica",7.8)
   self.canv.drawCentredString(w/2,4*mm,"Radiologista responsável - CRO-SP 113752")
 def apply_final_footer(pdf_bytes):
  # Rodapé institucional exclusivamente na última página.
  from pypdf import PdfReader, PdfWriter
  from reportlab.pdfgen import canvas
  reader=PdfReader(io.BytesIO(pdf_bytes)); writer=PdfWriter()
  total=len(reader.pages)
  for index,page in enumerate(reader.pages):
   if index==total-1:
    width=float(page.mediabox.width); height=float(page.mediabox.height)
    overlay=io.BytesIO(); cv=canvas.Canvas(overlay,pagesize=(width,height))
    cv.setStrokeColor(colors.HexColor("#DCE8EC")); cv.line(22*mm,24*mm,width-22*mm,24*mm)
    cv.setFillColor(colors.HexColor("#06394C")); cv.setFont("Helvetica-Bold",7.8)
    cv.drawCentredString(width/2,18*mm,"MALIBUB Imaginologia Odontológica")
    cv.setFillColor(colors.HexColor("#52666E")); cv.setFont("Helvetica",7.2)
    cv.drawCentredString(width/2,14*mm,"Assinado eletronicamente por Marina Bub - CRO-SP 113752")
    cv.setFont("Helvetica",6.8)
    cv.drawCentredString(width/2,9*mm,f"Data: {brasilia_stamp(e.signed_at or e.released_at)} - Protocolo {e.protocol or ''}")
    cv.save(); overlay.seek(0); page.merge_page(PdfReader(overlay).pages[0])
   writer.add_page(page)
  out=io.BytesIO(); writer.write(out); out.seek(0); return out
 if is_tmj_model:
  from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, KeepTogether
  from reportlab.lib.styles import ParagraphStyle
  from reportlab.lib.enums import TA_CENTER
  from reportlab.lib.units import mm
  from reportlab.lib import colors
  from xml.sax.saxutils import escape
  signed=brasilia_stamp(e.signed_at or e.released_at)
  W,H=A4
  from reportlab.platypus import Flowable
  class TMJInlineSignature(Flowable):
   def __init__(self):
    super().__init__(); self.width=W-44*mm; self.height=10*mm
   def draw(self):
    draw_report_signature(self.canv,self.width,baseline=0)
  def tmj_header_footer(canv,docobj):
   canv.saveState()
   navy=colors.HexColor("#06394C"); teal=colors.HexColor("#087B9B"); gold=colors.HexColor("#C99B3B")
   # Cabeçalho clínico discreto; a marca MALIBUB fica no fechamento do documento.
   if clinic and clinic.name:
    canv.setFillColor(colors.HexColor("#52666E")); canv.setFont("Helvetica",7.5)
    canv.drawRightString(W-22*mm,H-17*mm,str(clinic.name)[:70])
   canv.setFillColor(colors.black); canv.setFont("Helvetica-Bold",8.5)
   canv.drawString(22*mm,H-24*mm,f"Nome do paciente: {e.patient or ''}")
   canv.setFont("Helvetica",8.5)
   canv.drawString(22*mm,H-31*mm,f"Data de nasc.: {br_date(e.birth)}")
   canv.drawString(85*mm,H-31*mm,f"Data do exame: {br_date(e.exam_date)}")
   canv.drawString(22*mm,H-38*mm,f"Indicação clínica: {e.observation or ''}")
   canv.drawString(22*mm,H-45*mm,f"Dentista solicitante: {e.dentist or ''}")
   canv.setStrokeColor(colors.HexColor("#DCE8EC")); canv.setLineWidth(.5)
   canv.line(22*mm,H-49*mm,W-22*mm,H-49*mm)
   canv.restoreState()
  frame=Frame(22*mm,48*mm,W-44*mm,H-109*mm,leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0,id="tmj_body")
  tdoc=BaseDocTemplate(buf,pagesize=A4,leftMargin=22*mm,rightMargin=22*mm,topMargin=61*mm,bottomMargin=48*mm,title=f"{e.protocol} - Laudo TMJ",author="MALIBUB Imaginologia Odontológica")
  tdoc.addPageTemplates(PageTemplate(id="TMJ",frames=[frame],onPage=tmj_header_footer))
  normal=ParagraphStyle("tmjn",fontName="Helvetica",fontSize=9.2,leading=14,spaceAfter=4,textColor=colors.black)
  bold=ParagraphStyle("tmjb",parent=normal,fontName="Helvetica-Bold")
  center=ParagraphStyle("tmjc",parent=bold,alignment=TA_CENTER,fontSize=10,leading=13,spaceAfter=9)
  italic=ParagraphStyle("tmji",parent=normal,fontName="Helvetica-Oblique",spaceBefore=5,spaceAfter=7)
  story_tmj=[
   Paragraph("<u>TOMOGRAFIA COMPUTADORIZADA POR FEIXE CÔNICO</u>",center),
   Spacer(1,3*mm),
    Paragraph("<b>Técnica:</b> Estudo realizado por aquisição volumétrica cone beam da região solicitada, em cortes axiais paralelos ao rebordo alveolar e sem contraste. Realizadas reformatações panorâmicas e transversais e reconstruções em 3D.",normal),
   Spacer(1,4*mm),
   Paragraph("<b>Descrição do exame:</b>",bold)
  ]
  for markup,alignment in rich_report_blocks(e.report_html,e.report):
   sty=ParagraphStyle("rich_tmj",parent=normal,alignment={"left":0,"center":1,"right":2,"justify":4}.get(alignment,0))
   story_tmj.append(Paragraph(markup,sty))
  story_tmj += [
   Spacer(1,5*mm),
   Paragraph("Este relatório foi baseado em imagens axiais, tangenciais, interseccionais (transaxiais ou parassagitais) de acordo com volume obtido.",normal),
   Paragraph("As impressões encontram-se em escala 1:1 podendo as mensurações serem realizadas diretamente nas imagens.",normal),
   Paragraph("Os cortes transversais apresentam numerações no canto superior esquerdo e equivalem aos números constantes na parte superior da imagem panorâmica. Utilizando-se a escala milimetrada presente no lado direito dos cortes transversais, obtém-se o valor real da região desejada.",normal),
   Paragraph("<b>As mensurações são sugestivas devendo ficar a critério clínico a escolha do local, tamanho e angulação dos implantes.</b>",normal),
   Spacer(1,3*mm),
   Paragraph("É inerente a todo exame tomográfico, especialmente o de alta definição como este recebido, que estruturas metálicas de coroas protéticas, restaurações, núcleos e também de obturações endodônticas presentes nas regiões analisadas, formem imagens em forma de raios, prejudicando a avaliação das mesmas.",normal),
   Paragraph("“Há dados do paciente que somente o profissional solicitante do exame possui, confirmando ou não a interpretação das imagens pelo radiologista”",italic),
   Spacer(1,3*mm)
  ]
  tmj_signature_style=ParagraphStyle("tmj_signer",parent=normal,alignment=TA_CENTER,fontName="Helvetica-Bold",fontSize=10,leading=12,spaceAfter=2)
  tmj_sub_style=ParagraphStyle("tmj_sub",parent=normal,alignment=TA_CENTER,fontSize=8,leading=11,textColor=colors.HexColor("#657F89"),spaceAfter=1)
  story_tmj.append(KeepTogether([Spacer(1,3*mm),ReportSignature()]))
  tdoc.build(story_tmj)
  buf=apply_final_footer(buf.getvalue())
  return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"{e.protocol}_laudo.pdf")
 doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=22*mm,leftMargin=22*mm,topMargin=((clinic.report_top_mm or 72)*mm if has_pdf_model else 16*mm),bottomMargin=((clinic.report_bottom_mm or 48)*mm if has_pdf_model else 48*mm),title=f"{e.protocol} - Laudo MALIBUB",author="MALIBUB Imaginologia Odontológica")
 styles=getSampleStyleSheet(); navy=colors.HexColor("#06394C"); teal=colors.HexColor("#087B9B"); gold=colors.HexColor("#C99B3B")
 title=ParagraphStyle("t",parent=styles["Heading1"],alignment=TA_CENTER,textColor=navy,fontSize=16,leading=20); body=ParagraphStyle("b",parent=styles["BodyText"],fontSize=10,leading=15,textColor=colors.HexColor("#26383D"))
 story=[]
 # Quando a clínica não utiliza papel timbrado/modelo próprio, a logomarca
 # cadastrada passa a compor o cabeçalho do PDF padrão.
 if clinic and clinic.logo and not has_pdf_model:
  try:
   from reportlab.platypus import Image
   logo_bytes=storage_bytes(clinic.logo)
   logo_img=Image(io.BytesIO(logo_bytes))
   logo_img._restrictSize(48*mm,22*mm)
   story += [logo_img,Spacer(1,3*mm),Paragraph(escape(clinic.name or ""),ParagraphStyle("clinicbrand",parent=styles["Normal"],alignment=TA_CENTER,fontSize=9,textColor=teal)),Spacer(1,4*mm)]
  except Exception:
   story=[]
 model_path=None
 temp_model_path=None
 if clinic and clinic.report_model:
  if object_storage_enabled():
   if storage_exists(clinic.report_model):
    model_path=UPLOAD/("_model_"+uuid.uuid4().hex+Path(clinic.report_model).suffix)
    temp_model_path=model_path
    model_path.write_bytes(storage_bytes(clinic.report_model))
  else: model_path=UPLOAD/clinic.report_model
 if has_pdf_model and (not model_path or not model_path.exists()):
  return "O modelo PDF personalizado desta clínica não está disponível. Reenvie o modelo antes de gerar o laudo.",410
 if model_path and model_path.exists() and model_path.suffix.lower() in {".jpg",".jpeg",".png"}:
  from reportlab.platypus import Image
  try:
   bg=Image(str(model_path)); bg._restrictSize(170*mm,48*mm); story += [bg,Spacer(1,4*mm)]
  except Exception: pass
 if not story and not has_pdf_model:
  clinic_title=escape((clinic.name if clinic and clinic.name else "Clínica solicitante"))
  story=[Paragraph(clinic_title,title),Spacer(1,6*mm)]
 if not has_pdf_model:
  data=[["Protocolo",escape(e.protocol or "")],["Paciente",escape(e.patient or "")],["Sexo",escape(e.sex or "Não informado")],["Data de nascimento",escape(br_date(e.birth))],["Exame",escape(e.exam_type or "")],["Dentista solicitante",escape(e.dentist or "")],["Data do exame",escape(br_date(e.exam_date))]]
  t=Table(data,colWidths=[42*mm,120*mm]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.4,colors.HexColor("#DCE8EC")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F1F6F7")),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("PADDING",(0,0),(-1,-1),6)])); story += [t,Spacer(1,7*mm),Paragraph("LAUDO RADIOLÓGICO",ParagraphStyle("h",parent=title,alignment=0,fontSize=12,textColor=navy)),Spacer(1,2*mm)]
 if not has_pdf_model:
  for markup,alignment in rich_report_blocks(e.report_html,e.report):
   sty=ParagraphStyle("rich_body",parent=body,alignment={"left":0,"center":1,"right":2,"justify":4}.get(alignment,0))
   story.append(Paragraph(markup,sty))
 signer=escape(e.signed_by or "Dra. Marina"); signed=brasilia_stamp(e.signed_at or e.released_at)
 if not has_pdf_model:
  story.append(KeepTogether([Spacer(1,5*mm),ReportSignature()]))
  doc.build(story)
  buf=apply_final_footer(buf.getvalue())
 # Modelo PDF da clínica: o texto do campo "Laudo radiológico" deve ocupar
 # uma área própria logo após a descrição fixa, sem sobrepor o restante do modelo.
 # Para modelos que já contêm texto fixo abaixo da descrição (ex.: TMJ), o sistema
 # cria uma folha de continuação com o mesmo cabeçalho quando necessário.
 if model_path and model_path.exists() and model_path.suffix.lower()==".pdf":
  try:
   from pypdf import PdfReader, PdfWriter
   from reportlab.pdfgen import canvas
   base_reader=PdfReader(str(model_path)); final_writer=PdfWriter()
   # Renderização com os mesmos parágrafos estilizados dos demais laudos.
   blocks=rich_report_blocks(e.report_html,e.report)
   from reportlab.platypus import Paragraph
   from reportlab.lib.styles import ParagraphStyle
   from reportlab.lib.enums import TA_LEFT,TA_CENTER,TA_RIGHT,TA_JUSTIFY
   def make_block(markup,alignment,available_width):
    style=ParagraphStyle("clinic_rich",fontName="Helvetica",fontSize=9,leading=12,textColor=colors.HexColor("#111111"),alignment={"left":TA_LEFT,"center":TA_CENTER,"right":TA_RIGHT,"justify":TA_JUSTIFY}.get(alignment,TA_LEFT))
    p=Paragraph(markup,style);_,h=p.wrap(available_width,700*mm);return p,h
   first=base_reader.pages[0];width=float(first.mediabox.width);height=float(first.mediabox.height)
   left=22*mm; available_width=width-44*mm
   rendered=[make_block(markup,align,available_width) for markup,align in blocks]
   index=0;signature_done=False
   overlay=io.BytesIO();cv=canvas.Canvas(overlay,pagesize=(width,height))
   y=height-119*mm;min_y=height-139*mm
   while index<len(rendered):
    para,h=rendered[index]
    if y-h<min_y:break
    y-=h;para.drawOn(cv,left,y);y-=2*mm;index+=1
   # O modelo da clínica pode ter texto fixo abaixo da área editável.
   # Por segurança, a assinatura vai para a folha de continuação.
   cv.save();overlay.seek(0);first.merge_page(PdfReader(overlay).pages[0]);final_writer.add_page(first)
   for original_page in list(base_reader.pages)[1:]:final_writer.add_page(original_page)
   while index<len(rendered) or not signature_done:
    extra=io.BytesIO();cv=canvas.Canvas(extra,pagesize=A4);width,height=A4
    cv.setFont("Helvetica-Bold",11);cv.setFillColor(colors.HexColor("#111111"))
    cv.drawCentredString(width/2,height-20*mm,"LAUDO RADIOLÓGICO - CONTINUAÇÃO")
    cv.setFont("Helvetica",8)
    cv.drawString(22*mm,height-27*mm,f"Paciente: {(e.patient or '')[:60]}  |  Sexo: {(e.sex or '')[:20]}  |  Nascimento: {br_date(e.birth)}")
    cv.drawString(22*mm,height-31*mm,f"Dentista: {(e.dentist or '')[:45]}  |  Data do exame: {br_date(e.exam_date)}")
    cv.line(22*mm,height-34*mm,width-22*mm,height-34*mm)
    y=height-42*mm;available_width=width-44*mm
    while index<len(rendered):
     para,h=make_block(blocks[index][0],blocks[index][1],available_width)
     if y-h<66*mm:break
     y-=h;para.drawOn(cv,22*mm,y);y-=2*mm;index+=1
    if index==len(rendered) and y>=66*mm:
     draw_report_signature(cv,width,baseline=y-12*mm)
     cv.setFillColor(colors.HexColor("#06394C"));cv.setFont("Helvetica-Bold",9)
     cv.drawCentredString(width/2,y-16*mm,"Dra. Marina L. Bub")
     cv.setFillColor(colors.HexColor("#52666E"));cv.setFont("Helvetica",7.8)
     cv.drawCentredString(width/2,y-20*mm,"Radiologista responsável - CRO-SP 113752")
     signature_done=True
    if index<len(rendered) and y==height-42*mm:
     raise ValueError("Parágrafo do laudo excede a altura de uma página")
    cv.save();extra.seek(0);final_writer.add_page(PdfReader(extra).pages[0])
   merged=io.BytesIO(); final_writer.write(merged); merged.seek(0); buf=apply_final_footer(merged.getvalue())
  except Exception:
   return "Não foi possível gerar o PDF personalizado. Verifique o modelo de laudo cadastrado.",500
 print_mode=request.args.get("print")=="1"
 response=send_file(buf,mimetype="application/pdf",as_attachment=not print_mode,download_name=f"{e.protocol}_laudo.pdf")
 if print_mode:
  response.headers["Content-Disposition"]=f'inline; filename="{e.protocol}_laudo.pdf"'
 if temp_model_path and temp_model_path.exists():
  @response.call_on_close
  def _cleanup_temp_model():
   try: temp_model_path.unlink()
   except OSError: pass
 return response

@app.route("/result/<int:eid>")
def result(eid):
 if not session.get("uid"): return redirect("/")
 if session.get("role") not in {"Clinica","Radiologista"}: return redirect("/")
 e=Exam.query.get_or_404(eid)
 if session.get("role")=="Clinica" and e.clinic_id!=session.get("uid"): return redirect("/dashboard")
 if e.status!="Liberado": return redirect("/dashboard")
 ready=ExamFile.query.filter_by(exam_id=e.id,kind="exame_pronto").all()
 ready_html="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{html_escape(f.name)}'>" if f.name.lower().endswith(('.jpg','.jpeg')) else f"<iframe src='/exam-file/{f.id}' title='{html_escape(f.name)}'></iframe>") + "</div>") for f in ready)
 signed=brasilia_stamp(e.signed_at)
 body=f'''<section class="print-result"><h1>Resultado — {html_escape(e.protocol)}</h1><div class="card"><div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap"><div><h2 style="margin:0 0 6px">{html_escape(e.patient)}</h2><div class="muted"><b>Sexo:</b> {html_escape(e.sex or 'Não informado')} · <b>Nascimento:</b> {html_escape(br_date(e.birth) or '—')} · <b>Exame:</b> {html_escape(e.exam_type)} · <b>Dentista:</b> {html_escape(e.dentist or 'Dentista não informado')} · <b>Data do exame:</b> {html_escape(br_date(e.exam_date) or '—')}</div></div><span class="badge">{html_escape(e.status)}</span></div><hr><h3>Laudo radiológico</h3><div style="white-space:pre-wrap;min-height:220px;line-height:1.6">{html_escape(e.report or 'Laudo não informado.')}</div><div style="margin-top:22px;padding-top:16px;border-top:1px solid #dce8ec"><b>{html_escape(e.signed_by or 'Dra. Marina')}</b><br><span class="muted">Radiologista responsável · Assinado eletronicamente {signed}</span></div><hr><div class="no-print"><a class="btn gold" href="/result/{e.id}/pdf">Baixar laudo assinado em PDF</a><a class="btn" href="/result/{e.id}/pdf?print=1" target="_blank">Imprimir</a></div></div></section><section class="card viewer no-print"><h2>Exame pronto / Templates</h2><p class="muted">Arquivos finais disponibilizados pela radiologista.</p>{ready_html or '<div class="notice">Nenhum arquivo final foi anexado.</div>'}</section>'''
 return page(body)

@app.route("/finance",methods=["GET","POST"])
def finance():
 if session.get("role")!="Radiologista": return redirect("/")
 if request.method=="POST":
  category=request.form.get("category","Outros").strip()[:60]
  cost_class=request.form.get("cost_class","").strip()[:30]
  description=request.form.get("description","").strip()[:120]
  kind=request.form.get("kind","").strip()
  if kind not in {"Entrada","Saída"}:
   flash("Tipo de lançamento inválido."); return redirect("/finance")
  if not description:
   flash("Informe uma descrição."); return redirect("/finance")
  try:
   amount=float(request.form.get("amount") or 0)
   if amount < 0: raise ValueError
  except (TypeError,ValueError):
   flash("Informe um valor financeiro válido."); return redirect("/finance")
  label=" · ".join(x for x in (category,cost_class,description) if x)
  db.session.add(Finance(description=label[:200],kind=kind,amount=amount)); db.session.commit()
  return redirect("/finance")
 month=request.args.get("month","").strip()
 q=Finance.query
 if month:
  try:
   y,m=map(int,month.split("-")); first=datetime(y,m,1).date(); last=(datetime(y+1,1,1) if m==12 else datetime(y,m+1,1)).date()
   q=q.filter(Finance.date>=first,Finance.date<last)
  except Exception: month=""
 entries=q.order_by(Finance.date.desc()).all()
 ent=sum(x.amount for x in entries if x.kind=="Entrada"); sai=sum(x.amount for x in entries if x.kind=="Saída"); saldo=ent-sai
 infra_terms=("Registro","Hospedagem","Armazenamento","Domínio","Infraestrutura")
 fixed=sum(x.amount for x in entries if x.kind=="Saída" and " · Fixo · " in (" · "+(x.description or "")+" · "))
 variable=sum(x.amount for x in entries if x.kind=="Saída" and " · Variável · " in (" · "+(x.description or "")+" · "))
 infra=sum(x.amount for x in entries if x.kind=="Saída" and any((x.description or "").startswith(t+" ·") for t in infra_terms))
 exam_q=Exam.query.filter_by(status="Liberado")
 if month:
  exam_q=exam_q.filter(Exam.released_at>=datetime.combine(first,datetime.min.time()),Exam.released_at<datetime.combine(last,datetime.min.time()))
 released=exam_q.count()
 report_revenue=sum(x.amount for x in entries if x.kind=="Entrada" and ((x.description or "").startswith("Laudo ") or (x.description or "").startswith("Laudos ·")))
 ticket=(report_revenue/released) if released else 0
 variable_per_report=(variable/released) if released else 0
 contribution=ticket-variable_per_report
 break_even=(fixed/contribution) if contribution>0 else 0
 margem=(saldo/ent*100) if ent else 0
 health="POSITIVA" if saldo>0 else ("EQUILIBRADA" if saldo==0 else "NEGATIVA")
 clinics=User.query.filter_by(role="Clinica").order_by(User.name).all()
 clinic_options="".join("<option value='"+str(u.id)+"'>"+str(html_escape(u.name))+"</option>" for u in clinics)
 rows_parts=[]
 for x in entries:
  protected=x.kind=="Entrada" and ((x.description or "").startswith("Laudo ") or (x.description or "").startswith("Laudos ·"))
  if protected:
   action="<form method='post' action='/finance/"+str(x.id)+"/corrigir-valor' style='margin:0;display:flex;gap:6px;align-items:center'>"+csrf_field()+"<input type='number' name='amount' min='0.01' step='0.01' value='"+format(x.amount or 0,'.2f')+"' required style='width:110px;margin:0'><button type='submit' class='gold' style='margin:0'>Corrigir valor</button></form>"
  else:
   action="<form method='post' action='/finance/"+str(x.id)+"/excluir' style='margin:0' onsubmit=\"return confirm('Excluir este lançamento?')\">"+csrf_field()+"<button type='submit'>Excluir</button></form>"
  rows_parts.append("<tr><td>"+x.date.strftime("%d/%m/%Y")+"</td><td>"+str(html_escape(x.description or ""))+"</td><td>"+str(html_escape(x.kind or ""))+"</td><td>R$ "+format(x.amount,".2f")+"</td><td>"+action+"</td></tr>")
 rows="".join(rows_parts)
 body=f'''<h1>Financeiro MALIBUB</h1><p class="muted">Acompanhe receitas, custos da plataforma e saúde financeira.</p>
 <form method="get" class="card"><label>Período mensal<input type="month" name="month" value="{html_escape(month)}"></label><button type="submit">Filtrar</button><a class="btn" href="/finance">Todo o período</a></form>
 <div class="cards"><div class="card">Entradas<b>R$ {ent:.2f}</b></div><div class="card">Saídas<b>R$ {sai:.2f}</b></div><div class="card">Saldo<b>R$ {saldo:.2f}</b></div><div class="card">Infraestrutura<b>R$ {infra:.2f}</b></div><div class="card">Custos fixos<b>R$ {fixed:.2f}</b></div><div class="card">Custos variáveis<b>R$ {variable:.2f}</b></div><div class="card">Margem<b>{margem:.1f}%</b></div><div class="card">Saúde financeira<b>{health}</b></div><div class="card">Laudos liberados<b>{released}</b></div><div class="card">Receita de laudos<b>R$ {report_revenue:.2f}</b></div><div class="card">Ticket médio<b>R$ {ticket:.2f}</b></div><div class="card">Ponto de equilíbrio<b>{break_even:.1f} laudos</b></div></div>
 <div class="card"><h2>Relatório de produção para cobrança</h2><p class="muted">Gere o demonstrativo mensal em PDF com quantidade de laudos e valores da clínica.</p><form method="get" action="/finance/relatorio-producao"><div class="grid"><label>Clínica<select name="clinic_id" required><option value="">Selecione</option>{clinic_options}</select></label><label>Período<input type="month" name="month" value="{html_escape(month)}" required></label></div><button class="gold" type="submit">Gerar relatório PDF</button></form></div> <div class="card"><h2>Novo lançamento</h2><form method="post">{csrf_field()}<div class="grid"><label>Categoria<select name="category"><option>Laudos</option><option>Registro</option><option>Hospedagem</option><option>Armazenamento</option><option>Domínio</option><option>Infraestrutura</option><option>Marketing</option><option>Impostos</option><option>Outros</option></select></label><label>Classificação do custo<select name="cost_class"><option value="">Não se aplica</option><option>Fixo</option><option>Variável</option></select></label><label>Descrição<input name="description" placeholder="Ex.: renovação anual, mensalidade, consumo R2" required></label><label>Tipo<select name="kind"><option>Entrada</option><option>Saída</option></select></label><label>Valor (R$)<input type="number" min="0" step="0.01" name="amount" required></label></div><button class="gold">Adicionar lançamento</button></form></div>
 <div class="card"><h2>Movimentações</h2><table><tr><th>Data</th><th>Categoria / descrição</th><th>Tipo</th><th>Valor</th><th>Ação</th></tr>{rows or '<tr><td colspan="5">Nenhum lançamento neste período.</td></tr>'}</table></div>'''
 return page(body)

@app.route("/finance/relatorio-producao")
def finance_production_report():
 if session.get("role")!="Radiologista": return redirect("/")
 clinic_id=request.args.get("clinic_id",type=int)
 month=request.args.get("month","").strip()
 clinic=User.query.filter_by(id=clinic_id,role="Clinica").first() if clinic_id else None
 if not clinic or not month:
  flash("Selecione a clínica e o mês para gerar o relatório.")
  return redirect("/finance")
 try:
  y,m=map(int,month.split("-"))
  first=datetime(y,m,1)
  last=datetime(y+1,1,1) if m==12 else datetime(y,m+1,1)
 except Exception:
  flash("Período inválido.")
  return redirect("/finance")
 exams=Exam.query.filter(Exam.clinic_id==clinic.id,Exam.status=="Liberado",Exam.released_at>=first,Exam.released_at<last).order_by(Exam.released_at).all()
 from reportlab.lib.pagesizes import A4
 from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
 from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
 from reportlab.lib import colors
 from reportlab.lib.enums import TA_CENTER
 from reportlab.lib.units import mm
 from xml.sax.saxutils import escape
 values={}; billing_issues=[]
 for e in exams:
  item=Finance.query.filter_by(description=f"Laudo {e.protocol}",kind="Entrada").first()
  if not item:
   values[e.protocol]=None; billing_issues.append(f"{e.protocol}: lançamento financeiro ausente")
  elif item.amount is None or item.amount<=0:
   values[e.protocol]=item.amount or 0; billing_issues.append(f"{e.protocol}: valor zerado")
  else:
   values[e.protocol]=item.amount
 total=sum(v for v in values.values() if v is not None and v>0)
 buf=io.BytesIO()
 doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=16*mm,leftMargin=16*mm,topMargin=18*mm,bottomMargin=18*mm)
 styles=getSampleStyleSheet()
 title=ParagraphStyle("malibub_title",parent=styles["Title"],fontName="Helvetica-Bold",fontSize=17,leading=21,alignment=TA_CENTER,textColor=colors.HexColor("#087b9b"))
 story=[Paragraph("MALIBUB IMAGINOLOGIA ODONTOLÓGICA",title),Paragraph("Relatório de Produção por Período",styles["Heading2"]),Spacer(1,5*mm),Paragraph(f"<b>Clínica:</b> {escape(clinic.name)}",styles["BodyText"]),Paragraph(f"<b>Período:</b> {first.strftime('%d/%m/%Y')} a {(last-timedelta(days=1)).strftime('%d/%m/%Y')}",styles["BodyText"]),Paragraph(f"<b>Quantidade de laudos:</b> {len(exams)}",styles["BodyText"]),Spacer(1,5*mm)]
 data=[["Data","Protocolo","Exame","Valor"]]
 for e in exams:
  value=values[e.protocol]
  value_text="PENDENTE" if value is None or value<=0 else f"R$ {value:.2f}"
  data.append([(e.released_at or e.created_at).strftime("%d/%m/%Y"),e.protocol,e.exam_type or "-",value_text])
 data.append(["","","TOTAL VÁLIDO",f"R$ {total:.2f}"])
 table=Table(data,colWidths=[30*mm,42*mm,75*mm,30*mm],repeatRows=1)
 table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#087b9b")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(2,-1),(-1,-1),"Helvetica-Bold"),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#b8cbd2")),("VALIGN",(0,0),(-1,-1),"TOP"),("ALIGN",(-1,1),(-1,-1),"RIGHT"),("PADDING",(0,0),(-1,-1),6)]))
 story.extend([table,Spacer(1,7*mm)])
 if billing_issues:
  warning=ParagraphStyle("billing_warning",parent=styles["BodyText"],fontName="Helvetica-Bold",textColor=colors.HexColor("#9a5b00"),backColor=colors.HexColor("#fff4d6"),borderPadding=7,spaceAfter=5*mm)
  story.append(Paragraph("<b>ATENÇÃO:</b> Este relatório possui valor(es) pendente(s) de correção e não deve ser enviado para cobrança até a regularização: "+escape("; ".join(billing_issues))+".",warning))
 story.extend([Paragraph(f"<b>Valor total válido: R$ {total:.2f}</b>",styles["Heading2"]),Paragraph(f"Emitido em {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y %H:%M')} (horário de Brasília).",styles["BodyText"])])
 def production_footer(canv,docobj):
  canv.saveState()
  canv.setStrokeColor(colors.HexColor("#b8cbd2")); canv.setLineWidth(0.4); canv.line(16*mm,14*mm,A4[0]-16*mm,14*mm)
  canv.setFont("Helvetica",8); canv.setFillColor(colors.HexColor("#607d86"))
  canv.drawCentredString(A4[0]/2,9*mm,"MALIBUB Imaginologia Odontológica · Relatório de produção para conferência e cobrança.")
  canv.restoreState()
 doc.build(story,onFirstPage=production_footer,onLaterPages=production_footer); buf.seek(0)
 return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"MALIBUB_relatorio_{secure_filename(clinic.name)}_{month}.pdf")

@app.route("/finance/<int:fid>/corrigir-valor",methods=["POST"])
def finance_correct_value(fid):
 if session.get("role")!="Radiologista": return redirect("/")
 item=Finance.query.get_or_404(fid)
 if item.kind!="Entrada" or not (item.description or "").startswith("Laudo "):
  flash("Somente receitas automáticas de laudos podem ser corrigidas por esta ação.")
  return redirect("/finance")
 try:
  amount=float(request.form.get("amount") or 0)
  if amount<=0: raise ValueError
 except (TypeError,ValueError):
  flash("Informe um valor maior que R$ 0,00.")
  return redirect("/finance")
 item.amount=amount
 db.session.commit()
 flash(f"Valor de {item.description} corrigido para R$ {amount:.2f}.")
 return redirect("/finance")

@app.route("/finance/<int:fid>/excluir",methods=["POST"])
def finance_delete(fid):
 if session.get("role")!="Radiologista": return redirect("/")
 item=Finance.query.get_or_404(fid)
 if item.kind=="Entrada" and (item.description or "").startswith("Laudo "):
  flash("Receitas automáticas de laudos não podem ser excluídas manualmente.")
  return redirect("/finance")
 db.session.delete(item)
 db.session.commit()
 flash("Lançamento financeiro excluído.")
 return redirect("/finance")

@app.route("/minha-conta",methods=["GET","POST"])
def my_account():
 if not session.get("uid"): return redirect("/")
 u=User.query.get_or_404(session["uid"])
 if request.method=="POST":
  email=request.form.get("email","").strip().lower()[:120]; current=request.form.get("current_password","")[:256]; new=request.form.get("new_password","")[:256]
  if not check_password_hash(u.password,current): flash("Senha atual incorreta."); return redirect("/minha-conta")
  if email and email!=u.email:
   if User.query.filter_by(email=email).first(): flash("Este e-mail já está em uso."); return redirect("/minha-conta")
   u.email=email
  credentials_changed=False
  if new:
   if len(new)<10: flash("A nova senha deve ter pelo menos 10 caracteres."); return redirect("/minha-conta")
   u.password=generate_password_hash(new); credentials_changed=True
  db.session.commit()
  if credentials_changed:
   session.clear()
   flash("Senha atualizada. Entre novamente com a nova senha.")
   return redirect("/")
  flash("Dados de acesso atualizados."); return redirect("/minha-conta")
 body=f"""<h1>Minha conta</h1><div class='card'><form method='post'>{csrf_field()}<label>E-mail de acesso<input type='email' name='email' value='{html_escape(u.email)}' required></label><label>Senha atual<input type='password' name='current_password' required></label><label>Nova senha (opcional)<input type='password' name='new_password' minlength='10'></label><button class='gold'>Salvar alterações</button></form></div>"""
 return page(body)

@app.route("/logout",methods=["POST"])
def logout():
 session.clear(); return redirect("/")

if __name__=="__main__":
 import sys
 if len(sys.argv)>1 and sys.argv[1]=="purge-expired-files":
  with app.app_context():
   init()
   result=purge_expired_exam_files()
   print(f"retention_cleanup examined={result['examined']} deleted={result['deleted']} failed={result['failed']}")
   if result["failed"]: raise SystemExit(1)
 else:
  app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")))
