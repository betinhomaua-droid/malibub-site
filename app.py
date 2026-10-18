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
import os, uuid, io, secrets, zipfile
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
 response.headers["Content-Security-Policy"]="default-src 'self'; img-src 'self' data:; frame-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://*.r2.cloudflarestorage.com; form-action 'self'; base-uri 'self'; frame-ancestors 'self'"
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
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(100)); email=db.Column(db.String(120),unique=True); password=db.Column(db.String(255)); role=db.Column(db.String(30)); active=db.Column(db.Boolean,default=True); logo=db.Column(db.String(255)); logo_name=db.Column(db.String(255)); report_model=db.Column(db.String(255)); report_model_name=db.Column(db.String(255)); report_top_mm=db.Column(db.Integer,default=72); report_bottom_mm=db.Column(db.Integer,default=42); privacy_version=db.Column(db.String(20)); privacy_ack_at=db.Column(db.DateTime)
class ReportModel(db.Model):
 id=db.Column(db.Integer,primary_key=True); clinic_id=db.Column(db.Integer,index=True,nullable=False); name=db.Column(db.String(255)); stored=db.Column(db.String(255)); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class Exam(db.Model):
 id=db.Column(db.Integer,primary_key=True); protocol=db.Column(db.String(30),unique=True); patient=db.Column(db.String(120)); sex=db.Column(db.String(20)); birth=db.Column(db.String(20)); dentist=db.Column(db.String(120)); exam_date=db.Column(db.String(20)); exam_type=db.Column(db.String(100)); observation=db.Column(db.String(500)); priority=db.Column(db.String(20),default="NORMAL"); contracted_amount=db.Column(db.Float); status=db.Column(db.String(50),default="Enviado"); clinic_id=db.Column(db.Integer); due_at=db.Column(db.DateTime); report=db.Column(db.Text,default=""); released_at=db.Column(db.DateTime); signed_by=db.Column(db.String(120)); signed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=datetime.utcnow)
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
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS logo VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS logo_name VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE exam_file ADD COLUMN IF NOT EXISTS scan_status VARCHAR(20) DEFAULT 'PENDENTE'"))
   db.session.execute(db.text("ALTER TABLE exam_file ADD COLUMN IF NOT EXISTS scan_detail VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'NORMAL'"))
   db.session.execute(db.text("ALTER TABLE exam ADD COLUMN IF NOT EXISTS contracted_amount DOUBLE PRECISION"))
   db.session.execute(db.text("UPDATE \"user\" SET active=TRUE WHERE active IS NULL"))
   db.session.commit()
  except Exception:
   db.session.rollback()
 if db.engine.dialect.name=="sqlite":
  try:
   cols=[r[1] for r in db.session.execute(db.text("PRAGMA table_info(exam)")).fetchall()]
   if "signed_by" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN signed_by VARCHAR(120)"))
   if "signed_at" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN signed_at DATETIME"))
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
  if u and u.active is not False and password and check_password_hash(u.password,password):
   clear_login_failures(client_key)
   session.clear(); session.permanent=True
   session.update(uid=u.id,role=u.role,name=u.name,_csrf_token=secrets.token_urlsafe(32)); return redirect("/dashboard")
  record_login_failure(client_key)
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
 rows="".join(f"<tr><td>{html_escape(u.name)}</td><td>{html_escape(u.email)}</td><td>{'Ativo' if u.active is not False else 'Inativo'}</td><td><a class='btn' href='/admin/usuarios/{u.id}/editar'>Editar</a> <a class='btn' href='/admin/usuarios/{u.id}/precos'>Preços</a> <form method='post' action='/admin/usuarios/{u.id}/status' style='display:inline-block;margin:0'>{csrf_field()}<button type='submit'>{'Desativar' if u.active is not False else 'Ativar'}</button></form></td></tr>" for u in clinics)
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

@app.route("/dashboard")
def dashboard():
 if not session.get("uid"): return redirect("/")
 q=Exam.query
 if session["role"]=="Clinica": exams=q.filter_by(clinic_id=session["uid"]).order_by(Exam.created_at.desc()).all()
 else: exams=q.order_by(Exam.created_at.desc()).all()
 rows=""
 clinics={}
 if session["role"]=="Radiologista":
  clinic_ids=list({e.clinic_id for e in exams if e.clinic_id})
  clinics={u.id:u for u in User.query.filter(User.id.in_(clinic_ids)).all()} if clinic_ids else {}
 for e in exams:
  blocked=ExamFile.query.filter(ExamFile.exam_id==e.id,ExamFile.scan_status.in_(["SUSPEITO","INFECTADO"])).first()
  if session["role"]=="Clinica" and blocked:
   action="<span style='display:inline-block;background:#b42318;color:white;font-weight:800;padding:9px 12px;border-radius:8px'>SUSPEITO/INFECTADO</span>"
  else:
   primary_action=(f'<a class="btn" href="/report/{e.id}">Laudar</a>' if session["role"]=="Radiologista" and e.status!="Liberado" else (f'<a class="btn" href="/result/{e.id}">Resultado</a>' if e.status=="Liberado" else ""))
   delete_action=(f'<form method="post" action="/exam/{e.id}/excluir" style="display:inline" onsubmit="return confirm(\'Excluir definitivamente este exame, seus arquivos e o lançamento financeiro vinculado? Esta ação não pode ser desfeita.\')">{csrf_field()}<button type="submit" style="background:#b42318">Excluir</button></form>' if session["role"]=="Radiologista" else "")
   action=primary_action+delete_action
  if session["role"]=="Radiologista":
   clinic=clinics.get(e.clinic_id)
   if clinic and clinic.logo:
    clinic_cell=f"<div class='clinic-cell'><img src='/clinic-logo/{clinic.id}' alt='' loading='lazy'><span>{html_escape(clinic.name)}</span></div>"
   else:
    clinic_cell=html_escape(clinic.name if clinic else "Clínica não identificada")
   rows+=f"<tr><td>{html_escape(e.protocol)}</td><td>{html_escape(e.patient)}</td><td>{clinic_cell}</td><td>{html_escape(e.exam_type)}</td><td>{("<b style='color:#b42318'>URG</b><br>" if (e.priority or "NORMAL")=="URG" else "")+due_date_label(e.due_at,e.priority or "NORMAL")}</td><td><span class='badge'>{html_escape(e.status)}</span></td><td>{action}</td></tr>"
  else:
   rows+=f"<tr><td>{html_escape(e.protocol)}</td><td>{html_escape(e.patient)}</td><td>{html_escape(e.exam_type)}</td><td>{("<b style='color:#b42318'>URG</b><br>" if (e.priority or "NORMAL")=="URG" else "")+due_date_label(e.due_at,e.priority or "NORMAL")}</td><td><span class='badge'>{html_escape(e.status)}</span></td><td>{action}</td></tr>"
 headers="<tr><th>Protocolo</th><th>Paciente</th><th>Clínica</th><th>Exame</th><th>Entrega</th><th>Status</th><th>Ação</th></tr>" if session["role"]=="Radiologista" else "<tr><th>Protocolo</th><th>Paciente</th><th>Exame</th><th>Entrega</th><th>Status</th><th>Ação</th></tr>"
 colspan=7 if session["role"]=="Radiologista" else 6
 body=f'''<h1>Painel {'da Clínica' if session["role"]=="Clinica" else 'da Radiologista'}</h1><p>Olá, {html_escape(session["name"])}.</p>{'<a class="btn gold" href="/new">+ Novo Exame</a><a class="btn" href="/modelo-laudo">Modelo de laudo</a>' if session["role"]=="Clinica" else ''}<div class="card"><h2>Exames</h2><table>{headers}{rows or f'<tr><td colspan={colspan}>Nenhum exame.</td></tr>'}</table></div>'''
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

@app.post("/new/direct-upload-url")
def direct_upload_url():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 if not object_storage_enabled(): return {"error":"storage_unavailable"},503
 data=request.get_json(silent=True) or {}
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
 r2_client().head_object(Bucket=R2_BUCKET,Key=key)
 return key,name

@app.post("/new/direct-finalize")
def direct_upload_finalize():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 data=request.get_json(silent=True) or {}; files=data.get("files") or []; request_files=data.get("request_files") or []
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
 body=f'''<h1>Novo Exame</h1><div class="card"><form id="exam-form" method="post" enctype="multipart/form-data">{csrf_field()}<div class="grid"><label>Nome do paciente<input name="patient" required></label><label>Sexo<select name="sex"><option>Feminino</option><option>Masculino</option><option>Não informado</option></select></label><label>Data de nascimento<input type="date" name="birth" required></label><label>Dentista solicitante<input name="dentist" required></label><label>Data do exame<input type="date" name="exam_date" required></label><div class="grid"><label>Tipo de exame<select name="exam_type" required>{exam_type_options}</select></label><label>Prazo<select name="priority" required><option value="NORMAL">Normal — até 2 dias úteis</option><option value="URG">URG — até 24h (+50% do valor do exame)</option></select></label></div></div><label>Observação / motivo <span class="muted">(Avaliação de Maxila/Mandíbula, Exodontia dos 38 e 48, Implante na região do dente XX, ATM etc.)</span><textarea name="observation" maxlength="500"></textarea></label>
<div class="card" style="margin-top:18px"><h3>Requisição / pedido do dentista <span style="color:#b42318">*</span></h3><p class="muted">Obrigatório para enviar o exame. Se o pedido tiver mais de uma página, selecione todos os arquivos. Formatos: PDF, JPG ou PNG.</p><input id="dentist-request" type="file" name="dentist_request" multiple accept=".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png" style="display:none"><div style="display:flex;gap:10px;flex-wrap:wrap"><button type="button" class="blue" id="pick-request">Selecionar arquivos</button><button type="button" class="blue" id="pick-request-more">Adicionar mais arquivos</button></div><div id="request-status" class="notice" style="display:none;margin-top:10px"></div><div id="request-list" style="margin-top:10px"></div></div>
<div class="card" style="margin-top:18px"><h3>Arquivos do exame</h3><p class="muted">Adicione imagens, DICOM, PDF, ZIP ou RAR. Você pode combinar vários arquivos no mesmo exame.</p>
<input id="exam-files" type="file" multiple accept=".jpg,.jpeg,.png,.pdf,.dcm,.zip,.rar" style="display:none">
<input id="exam-folder" type="file" multiple webkitdirectory directory style="display:none">
<div style="display:flex;gap:10px;flex-wrap:wrap"><button type="button" class="blue" id="pick-files">Selecionar arquivos</button><button type="button" class="blue" id="pick-folder">Selecionar pasta</button><button type="button" class="blue" id="pick-more">Adicionar mais arquivos</button></div>
<div id="file-summary" class="notice" style="display:none;margin-top:12px"></div><div id="file-list" style="margin-top:10px"></div></div>
<div id="upload-progress" class="notice" style="display:none"></div><p class="muted" style="margin-top:14px">Ao enviar, a Clínica confirma que está autorizada a encaminhar os dados e arquivos necessários à execução do serviço solicitado.</p><button id="send-exam" class="gold">Enviar exame</button></form></div>
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
   const requestFiles=[];
   requestStatus.style.display="block";
   for(let ri=0;ri<selectedRequests.length;ri++){{
    const req=selectedRequests[ri];requestStatus.textContent="Enviando requisição "+(ri+1)+" de "+selectedRequests.length+"...";
    const ra=await fetch("/new/direct-upload-url",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify({{name:req.name,content_type:req.type||"application/octet-stream",kind:"request"}})}});if(!ra.ok)throw new Error("request_auth");const rs=await ra.json();
    const rp=await fetch(rs.url,{{method:"PUT",headers:{{"Content-Type":rs.content_type}},body:req}});if(!rp.ok)throw new Error("request_put");requestFiles.push({{key:rs.key,name:req.name,grant:rs.grant}});
   }}
   requestStatus.textContent=selectedRequests.length+" arquivo(s) da requisição enviado(s).";
   const uploaded=[];
   for(let i=0;i<selected.length;i++){{
    const file=selected[i].file;box.textContent="Enviando arquivo "+(i+1)+" de "+selected.length+" • "+fmt(file.size);
    const a=await fetch("/new/direct-upload-url",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify({{name:file.name,content_type:file.type||"application/octet-stream",kind:"exam"}})}});if(!a.ok)throw new Error("auth");const s=await a.json();
    const p=await fetch(s.url,{{method:"PUT",headers:{{"Content-Type":s.content_type}},body:file}});if(!p.ok)throw new Error("put");uploaded.push({{key:s.key,name:file.name,grant:s.grant}});
   }}
   box.textContent="Finalizando envio...";const fd=new FormData(form),payload={{files:uploaded,request_files:requestFiles}};["patient","sex","birth","dentist","exam_date","exam_type","priority","observation"].forEach(k=>payload[k]=fd.get(k)||"");
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
  try:
   raw_amount=request.form.get("amount","").strip()
   if not raw_amount: raise ValueError
   amount=float(raw_amount)
   if amount <= 0: raise ValueError
  except (TypeError,ValueError):
   flash("Informe o valor do laudo. Para evitar cobrança incorreta, o valor deve ser maior que R$ 0,00.")
   return redirect(url_for("report",eid=e.id))
  e.report=report_text; e.status="Liberado"; e.released_at=datetime.utcnow(); e.signed_by=session.get("name") or "Dra. Marina"; e.signed_at=datetime.utcnow()
  db.session.flush()
  check=result_pdf(e.id)
  if getattr(check,"status_code",200) >= 400:
   db.session.rollback()
   flash("PDF final indisponível. O exame não foi liberado nem faturado.")
   return redirect(url_for("report",eid=e.id))
  existing_revenue=Finance.query.filter_by(description=f"Laudo {e.protocol}",kind="Entrada").first()
  if not existing_revenue:
   db.session.add(Finance(description=f"Laudo {e.protocol}",kind="Entrada",amount=amount))
  db.session.commit(); return redirect("/dashboard")
 imgs="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><span class='badge'>{html_escape(f.scan_status or 'NAO_VERIFICADO')}</span><form method='post' action='/exam-file/{f.id}/scan' style='display:inline'>{csrf_field()}<button type='submit'>Verificar com antivírus</button></form><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{html_escape(f.name)}'>" if f.name.lower().endswith(('.jpg','.jpeg','.png','.webp')) else (f"<iframe src='/exam-file/{f.id}' title='{html_escape(f.name)}'></iframe>" if f.name.lower().endswith('.pdf') else "<div class='notice'>Pré-visualização indisponível para este formato. Use Abrir ou Baixar.</div>")) + "</div>") for f in files)
 request_html="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{html_escape(f.name)}'>" if f.name.lower().endswith(('.jpg','.jpeg','.png')) else f"<iframe src='/exam-file/{f.id}' title='{html_escape(f.name)}'></iframe>") + "</div>") for f in request_files)
 ready_html="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a><form method='post' action='/report/{e.id}/exame-pronto/{f.id}/excluir' style='display:inline-block;margin:0' onsubmit=\"return confirm('Excluir este anexo individualmente? Esta ação não pode ser desfeita.')\">{csrf_field()}<button type='submit'>Excluir</button></form></div>" + (f"<img src='/exam-file/{f.id}'>" if f.name.lower().endswith(('.jpg','.jpeg')) else f"<iframe src='/exam-file/{f.id}'></iframe>") + "</div>") for f in ready_files)
 clinic=User.query.get(e.clinic_id); price=ClinicPrice.query.filter_by(clinic_id=e.clinic_id,exam_type=e.exam_type,active=True).first(); suggested_amount=(e.contracted_amount if e.contracted_amount is not None else ((price.amount*(1.5 if (e.priority or "NORMAL")=="URG" else 1.0)) if price else None)); model_link=(f"<a class='btn' href='/modelo-laudo/arquivo?exam={e.id}' target='_blank'>Ver modelo de laudo da clínica</a>" if clinic and clinic.report_model else "<span class='muted'>Clínica sem modelo de laudo cadastrado.</span>")
 body=f'''<h1>Ambiente da Radiologista — {html_escape(e.protocol)}</h1><div style="margin-bottom:12px">{model_link}</div><div class="card"><h3 style="margin-top:0">Dados do paciente</h3><div class="grid"><div><b>Paciente</b><br>{html_escape(e.patient or '—')}</div><div><b>Sexo</b><br>{html_escape(e.sex or 'Não informado')}</div><div><b>Data de nascimento</b><br>{html_escape(br_date(e.birth) or '—')}</div><div><b>Dentista solicitante</b><br>{html_escape(e.dentist or '—')}</div><div><b>Data do exame</b><br>{html_escape(br_date(e.exam_date) or '—')}</div><div><b>Tipo de exame</b><br>{html_escape(e.exam_type or '—')}</div></div><p style="margin-bottom:0"><b>Prazo:</b> {'URG — até 24h (+50%)' if (e.priority or 'NORMAL')=='URG' else 'Normal — até 2 dias úteis'}<br><b>Observação / motivo:</b> <span class="muted">{html_escape(e.observation or 'Sem observação clínica.')}</span></p></div><div class="workspace"><section class="card viewer"><h2>Requisição / pedido do dentista</h2><p class="muted">Documento(s) enviado(s) pela clínica com a solicitação do profissional.</p>{request_html or '<div class="notice">Nenhuma requisição anexada. Exames anteriores à obrigatoriedade podem não possuir este documento.</div>'}<hr style="margin:24px 0;border:0;border-top:1px solid #dce8ec"><h2>Imagens / arquivos do exame</h2>{imgs or 'Nenhum anexo.'}<hr style="margin:24px 0;border:0;border-top:1px solid #dce8ec"><h2>Exame pronto / Templates</h2><p class="muted">Anexe o exame final produzido pela radiologista em JPG/JPEG e/ou PDF. Os arquivos ficarão vinculados a este exame.</p><form method="post" action="/report/{e.id}/exame-pronto" enctype="multipart/form-data">{csrf_field()}<input type="file" name="finished_files" accept=".jpg,.jpeg,.pdf,image/jpeg,application/pdf" multiple required><button class="gold" type="submit">Anexar exame pronto</button></form>{ready_html or '<div class="notice">Nenhum template/exame pronto anexado ainda.</div>'}</section><section class="card editor"><h2>Laudo escrito</h2><form method="post">{csrf_field()}<textarea name="report" placeholder="Digite o laudo..." required>{html_escape(e.report or '')}</textarea><label>Valor do laudo (R$)<input type="number" min="0.01" step="0.01" name="amount" value="{format(suggested_amount,'.2f') if suggested_amount is not None else ''}" placeholder="0,00" required></label><p class="muted">{'Valor contratado desta clínica para este tipo de exame, preenchido automaticamente.' if suggested_amount is not None else 'Sem preço contratado para este tipo de exame. Informe o valor antes de liberar.'} O valor será usado no Financeiro e no relatório de cobrança da clínica.</p><div class="editor-actions"><button type="button" onclick="localStorage.setItem('malibub_draft_{e.id}',document.querySelector('[name=report]').value);this.textContent='Rascunho salvo ✓'">Salvar rascunho</button><button type="submit" formaction="/report/{e.id}/preview-pdf" formmethod="post" formtarget="_blank">Visualizar laudo</button><button class="gold" type="submit">Finalizar e liberar</button></div></form><script>const ta=document.querySelector('[name=report]');if(!ta.value)ta.value=localStorage.getItem('malibub_draft_{e.id}')||'';</script></section></div>'''
 return page(body)

@app.route("/report/<int:eid>/preview-pdf",methods=["POST"])
def preview_report_pdf(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 # Salva somente uma prévia temporária do texto no registro para reutilizar o mesmo gerador.
 old_report=e.report; old_status=e.status; old_signed_by=e.signed_by; old_signed_at=e.signed_at; old_released=e.released_at
 e.report=request.form.get("report","")
 e.status="Liberado"; e.signed_by=session.get("name") or "Dra. Marina"; e.signed_at=datetime.utcnow(); e.released_at=e.signed_at
 db.session.flush()
 try:
  response=result_pdf(eid)
 finally:
  e.report=old_report; e.status=old_status; e.signed_by=old_signed_by; e.signed_at=old_signed_at; e.released_at=old_released
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
 from reportlab.lib.pagesizes import A4
 from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
 from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
 from reportlab.lib import colors
 from reportlab.lib.enums import TA_CENTER
 from reportlab.lib.units import mm
 from xml.sax.saxutils import escape
 buf=io.BytesIO(); clinic=User.query.get(e.clinic_id)
 model_name=(clinic.report_model_name or "").lower() if clinic else ""
 is_tmj_model=("laudotmj" in model_name or "tmj" in model_name)
 has_pdf_model=bool(clinic and clinic.report_model and Path(clinic.report_model).suffix.lower()==".pdf")
 # O modelo TMJ é reconstruído como documento fluido: o texto digitado no laudo
 # passa a fazer parte do fluxo do documento, empurrando o conteúdo seguinte e
 # criando novas páginas automaticamente, em vez de ser desenhado por cima do PDF.
 if is_tmj_model:
  from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, KeepTogether
  from reportlab.lib.styles import ParagraphStyle
  from reportlab.lib.enums import TA_CENTER
  from reportlab.lib.units import mm
  from reportlab.lib import colors
  from xml.sax.saxutils import escape
  signed=brasilia_stamp(e.signed_at or e.released_at)
  W,H=A4
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
   # Rodapé em três linhas independentes, com área exclusiva.
   canv.setStrokeColor(colors.HexColor("#DCE8EC")); canv.setLineWidth(.5)
   canv.line(22*mm,18*mm,W-22*mm,18*mm)
   canv.setFillColor(navy); canv.setFont("Helvetica-Bold",7.8)
   canv.drawCentredString(W/2,14*mm,"MALIBUB Imaginologia Odontológica")
   canv.setFillColor(colors.HexColor("#52666E")); canv.setFont("Helvetica-Bold",7.3)
   canv.drawCentredString(W/2,10.5*mm,"Assinado eletronicamente por Marina Bub · CROSP 113752")
   canv.setFont("Helvetica",6.8)
   canv.drawCentredString(W/2,7*mm,f"Data: {signed} · Protocolo {e.protocol or ''}")
   canv.setFillColor(colors.HexColor("#7B8C93")); canv.setFont("Helvetica",6.5)
   canv.drawRightString(W-22*mm,7*mm,f"Página {docobj.page}")
   canv.restoreState()
  frame=Frame(22*mm,23*mm,W-44*mm,H-84*mm,leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0,id="tmj_body")
  tdoc=BaseDocTemplate(buf,pagesize=A4,leftMargin=22*mm,rightMargin=22*mm,topMargin=61*mm,bottomMargin=23*mm,title=f"{e.protocol} - Laudo TMJ",author="MALIBUB Imaginologia Odontológica")
  tdoc.addPageTemplates(PageTemplate(id="TMJ",frames=[frame],onPage=tmj_header_footer))
  normal=ParagraphStyle("tmjn",fontName="Helvetica",fontSize=9.2,leading=14,spaceAfter=4,textColor=colors.black)
  bold=ParagraphStyle("tmjb",parent=normal,fontName="Helvetica-Bold")
  center=ParagraphStyle("tmjc",parent=bold,alignment=TA_CENTER,fontSize=10,leading=13,spaceAfter=9)
  italic=ParagraphStyle("tmji",parent=normal,fontName="Helvetica-Oblique",spaceBefore=5,spaceAfter=7)
  story_tmj=[
   Paragraph("<u>TOMOGRAFIA COMPUTADORIZADA POR FEIXE CÔNICO DA MANDÍBULA</u>",center),
   Spacer(1,3*mm),
   Paragraph("<b>Técnica:</b> Estudo realizado por aquisição volumétrica cone beam da região solicitada, em cortes axiais de 0,12 mm de espessura, paralelos ao rebordo alveolar e sem contraste. Realizadas reformatações panorâmicas e transversais com 2,0mm de distância entre os cortes (pode ser alterado para se obter melhor imagem) e reconstruções em 3D.",normal),
   Spacer(1,4*mm),
   Paragraph("<b>Descrição do exame:</b>",bold)
  ]
  for raw in (e.report or "").splitlines():
   story_tmj.append(Paragraph(escape(raw) if raw.strip() else "&nbsp;",normal))
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
  tdoc.build(story_tmj)
  buf.seek(0)
  return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"{e.protocol}_laudo.pdf")
 doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=22*mm,leftMargin=22*mm,topMargin=((clinic.report_top_mm or 72)*mm if has_pdf_model else 16*mm),bottomMargin=((clinic.report_bottom_mm or 42)*mm if has_pdf_model else 18*mm),title=f"{e.protocol} - Laudo MALIBUB",author="MALIBUB Imaginologia Odontológica")
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
  for line in (e.report or "").splitlines(): story.append(Paragraph(escape(line) or "&nbsp;",body))
 signer=escape(e.signed_by or "Dra. Marina"); signed=brasilia_stamp(e.signed_at or e.released_at)
 if not has_pdf_model:
  signature_bytes=io.BytesIO(__import__("base64").b64decode("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[... ELLIPSIZATION ...]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"))
  from reportlab.platypus import Image as RLImage
  signature_img=RLImage(signature_bytes,width=60*mm,height=27.2*mm)
  signature_img.hAlign="CENTER"
  story += [Spacer(1,6*mm),signature_img,Paragraph(f"<b>{signer}</b>",ParagraphStyle("sig",parent=body,alignment=TA_CENTER,textColor=navy)),Paragraph("Radiologista responsável",ParagraphStyle("sig2",parent=styles["Normal"],alignment=TA_CENTER,fontSize=8,textColor=colors.HexColor("#657F89"))),Spacer(1,3*mm),Paragraph(f"Assinado eletronicamente em {escape(signed)}",ParagraphStyle("f",parent=styles["Normal"],fontSize=8,textColor=colors.HexColor("#657F89"))),Paragraph(f"Validação MALIBUB · Protocolo {escape(e.protocol or '')}",ParagraphStyle("f3",parent=styles["Normal"],fontSize=7.5,textColor=colors.HexColor("#657F89"))),Spacer(1,2*mm),Paragraph((escape(clinic.name)+" · MALIBUB Imaginologia Odontológica") if clinic else "MALIBUB Imaginologia Odontológica",ParagraphStyle("f2",parent=styles["Normal"],fontSize=8,textColor=gold))]
 else:
  # No modelo personalizado, a confirmação da assinatura é aplicada depois,
  # como rodapé fixo em todas as páginas do PDF final.
  pass
 if not has_pdf_model:
  doc.build(story)
  buf.seek(0)
 # Modelo PDF da clínica: o texto do campo "Laudo radiológico" deve ocupar
 # uma área própria logo após a descrição fixa, sem sobrepor o restante do modelo.
 # Para modelos que já contêm texto fixo abaixo da descrição (ex.: TMJ), o sistema
 # cria uma folha de continuação com o mesmo cabeçalho quando necessário.
 if model_path and model_path.exists() and model_path.suffix.lower()==".pdf":
  try:
   from pypdf import PdfReader, PdfWriter
   from reportlab.pdfgen import canvas
   base_reader=PdfReader(str(model_path)); final_writer=PdfWriter()
   report_lines=[]; max_chars=92
   for raw in (e.report or "").splitlines():
    words=raw.split(); line=""
    if not words: report_lines.append(""); continue
    for word in words:
     test=(line+" "+word).strip()
     if len(test)>max_chars and line: report_lines.append(line); line=word
     else: line=test
    report_lines.append(line)
   # Primeira página TMJ: somente o espaço livre entre a descrição fixa e o texto técnico seguinte.
   first=base_reader.pages[0]; width=float(first.mediabox.width); height=float(first.mediabox.height)
   overlay=io.BytesIO(); cv=canvas.Canvas(overlay,pagesize=(width,height))
   left=22*mm; y=height-119*mm; min_y=height-139*mm
   cv.setFont("Helvetica",9); cv.setFillColor(colors.HexColor("#111111"))
   line_index=0
   while line_index<len(report_lines) and y>min_y:
    cv.drawString(left,y,report_lines[line_index][:max_chars]); line_index+=1; y-=4.4*mm
   cv.setFont("Helvetica",7.5); cv.setFillColor(colors.HexColor("#52666E"))
   cv.drawCentredString(width/2,10*mm,f"Assinado eletronicamente por {e.signed_by or 'Dra. Marina'}")
   cv.drawCentredString(width/2,6.5*mm,f"Data: {signed} · Protocolo {e.protocol or ''}")
   cv.save(); overlay.seek(0); first.merge_page(PdfReader(overlay).pages[0]); final_writer.add_page(first)
   # Mantém eventuais páginas originais seguintes.
   for original_page in list(base_reader.pages)[1:]: final_writer.add_page(original_page)
   # Continuação: página limpa com cabeçalho textual da clínica, sem repetir os parágrafos fixos.
   while line_index<len(report_lines):
    extra=io.BytesIO(); cv=canvas.Canvas(extra,pagesize=A4); width,height=A4
    cv.setFont("Helvetica-Bold",11); cv.setFillColor(colors.HexColor("#111111"))
    cv.drawCentredString(width/2,height-20*mm,"LAUDO RADIOLÓGICO — CONTINUAÇÃO")
    cv.setFont("Helvetica",8); cv.drawString(22*mm,height-27*mm,f"Paciente: {e.patient}  |  Sexo: {e.sex or 'Não informado'}  |  Nascimento: {br_date(e.birth)}"); cv.drawString(22*mm,height-31*mm,f"Dentista: {e.dentist or ''}  |  Data do exame: {br_date(e.exam_date)}  |  Exame: {e.exam_type or ''}")
    cv.line(22*mm,height-34*mm,width-22*mm,height-34*mm)
    y=height-42*mm; cv.setFont("Helvetica",9)
    while line_index<len(report_lines) and y>25*mm:
     cv.drawString(22*mm,y,report_lines[line_index][:max_chars]); line_index+=1; y-=4.4*mm
    cv.setFont("Helvetica",7.5); cv.setFillColor(colors.HexColor("#52666E"))
    cv.drawCentredString(width/2,10*mm,f"Assinado eletronicamente por {e.signed_by or 'Dra. Marina'}")
    cv.drawCentredString(width/2,6.5*mm,f"Data: {signed} · Protocolo {e.protocol or ''}")
    cv.save(); extra.seek(0); final_writer.add_page(PdfReader(extra).pages[0])
   merged=io.BytesIO(); final_writer.write(merged); merged.seek(0); buf=merged
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
