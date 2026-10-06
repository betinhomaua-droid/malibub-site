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
MALWARE_SCANNER_URL=os.getenv("MALWARE_SCANNER_URL","").rstrip("/")
MALWARE_SCANNER_TOKEN=os.getenv("MALWARE_SCANNER_TOKEN","")
MALWARE_SCAN_REQUIRED=os.getenv("MALWARE_SCAN_REQUIRED","false").lower()=="true"
app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
app.config["SESSION_COOKIE_SECURE"]=APP_ENV=="production"
app.config["PERMANENT_SESSION_LIFETIME"]=timedelta(hours=8)
db=SQLAlchemy(app)
UPLOAD=Path(app.instance_path)/"uploads"; UPLOAD.mkdir(parents=True,exist_ok=True)
R2_BUCKET=os.getenv("R2_BUCKET","")
R2_ENDPOINT_URL=os.getenv("R2_ENDPOINT_URL","")
def object_storage_enabled():
 return all([R2_BUCKET,R2_ENDPOINT_URL,os.getenv("R2_ACCESS_KEY_ID"),os.getenv("R2_SECRET_ACCESS_KEY")])
def r2_client():
 return boto3.client("s3",endpoint_url=R2_ENDPOINT_URL,aws_access_key_id=os.getenv("R2_ACCESS_KEY_ID"),aws_secret_access_key=os.getenv("R2_SECRET_ACCESS_KEY"),region_name="auto")
def ensure_r2_retention_lifecycle():
 if not object_storage_enabled(): return False
 try:
  r2_client().put_bucket_lifecycle_configuration(
   Bucket=R2_BUCKET,
   LifecycleConfiguration={"Rules":[{
    "ID":"malibub-delete-after-90-days",
    "Status":"Enabled",
    "Filter":{"Prefix":""},
    "Expiration":{"Days":AUTO_PURGE_DAYS}
   }]}
  )
  app.logger.info("r2_retention_lifecycle_ready days=%s",AUTO_PURGE_DAYS)
  return True
 except Exception as exc:
  app.logger.warning("r2_retention_lifecycle_failed error_type=%s",type(exc).__name__)
  return False
def ensure_r2_browser_cors():
 if not object_storage_enabled(): return False
 try:
  r2_client().put_bucket_cors(Bucket=R2_BUCKET,CORSConfiguration={"CORSRules":[{"AllowedOrigins":["https://portal.malibub.com.br"],"AllowedMethods":["PUT"],"AllowedHeaders":["Content-Type"],"ExposeHeaders":["ETag"],"MaxAgeSeconds":3600}]})
  return True
 except Exception as exc:
  app.logger.warning("r2_cors_setup_failed error_type=%s",type(exc).__name__)
  return False
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

def cleanup_expired_files():
 cutoff=datetime.utcnow()-timedelta(days=AUTO_PURGE_DAYS)
 deleted=0
 for item in ExamFile.query.all():
  exam=Exam.query.get(item.exam_id)
  created=getattr(exam,"created_at",None)
  if created and created < cutoff:
   # Registros bloqueados por malware não possuem objeto no armazenamento.
   # Evita tentar excluir uma chave vazia no R2 durante a rotina de retenção.
   if item.stored:
    try: storage_delete(item.stored)
    except Exception: continue
   db.session.delete(item); deleted+=1
 db.session.commit()
 return deleted

@app.cli.command("cleanup-expired-files")
def cleanup_expired_files_command():
 print(f"{cleanup_expired_files()} arquivo(s) removido(s) pela política de retenção.")

_last_retention_cleanup=None
@app.before_request
def automatic_retention_cleanup():
 global _last_retention_cleanup
 now=datetime.utcnow()
 if _last_retention_cleanup and now-_last_retention_cleanup < timedelta(hours=24): return
 try:
  cleanup_expired_files(); _last_retention_cleanup=now
 except Exception:
  db.session.rollback()

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
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(100)); email=db.Column(db.String(120),unique=True); password=db.Column(db.String(255)); role=db.Column(db.String(30)); active=db.Column(db.Boolean,default=True); logo=db.Column(db.String(255)); logo_name=db.Column(db.String(255)); report_model=db.Column(db.String(255)); report_model_name=db.Column(db.String(255)); report_top_mm=db.Column(db.Integer,default=72); report_bottom_mm=db.Column(db.Integer,default=42)
class Exam(db.Model):
 id=db.Column(db.Integer,primary_key=True); protocol=db.Column(db.String(30),unique=True); patient=db.Column(db.String(120)); sex=db.Column(db.String(20)); birth=db.Column(db.String(20)); dentist=db.Column(db.String(120)); exam_date=db.Column(db.String(20)); exam_type=db.Column(db.String(100)); observation=db.Column(db.String(500)); status=db.Column(db.String(50),default="Enviado"); clinic_id=db.Column(db.Integer); due_at=db.Column(db.DateTime); report=db.Column(db.Text,default=""); released_at=db.Column(db.DateTime); signed_by=db.Column(db.String(120)); signed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class ExamFile(db.Model):
 id=db.Column(db.Integer,primary_key=True); exam_id=db.Column(db.Integer); name=db.Column(db.String(255)); stored=db.Column(db.String(255)); kind=db.Column(db.String(30),default="entrada"); uploaded_by=db.Column(db.String(100)); scan_status=db.Column(db.String(20),default="PENDENTE"); scan_detail=db.Column(db.String(255))
class Finance(db.Model):
 id=db.Column(db.Integer,primary_key=True); date=db.Column(db.Date,default=datetime.utcnow().date); description=db.Column(db.String(200)); kind=db.Column(db.String(20)); amount=db.Column(db.Float,default=0)
class ClinicPrice(db.Model):
 id=db.Column(db.Integer,primary_key=True); clinic_id=db.Column(db.Integer,index=True,nullable=False); exam_type=db.Column(db.String(100),nullable=False); amount=db.Column(db.Float,nullable=False); active=db.Column(db.Boolean,default=True); __table_args__=(db.UniqueConstraint("clinic_id","exam_type",name="uq_clinic_exam_price"),)

CSS="""*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#f4f8fa;color:#153847}a{text-decoration:none;color:#087b9b}.shell{display:grid;grid-template-columns:220px 1fr;min-height:100vh}aside{background:linear-gradient(180deg,#06394c,#087b9b);color:white;padding:28px 20px}aside a{color:white;display:block;margin:20px 0}.brand{font-size:25px;font-weight:800}.brand span{display:block;font-weight:400}.brand small{display:block;font-size:10px;margin-top:8px}main{padding:32px;max-width:1500px}.card{background:white;border:1px solid #dce8ec;border-radius:16px;padding:22px;margin-bottom:18px;box-shadow:0 5px 18px #0c40540d}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}input,select,textarea{width:100%;padding:11px;border:1px solid #cbdde3;border-radius:8px;margin-top:6px}label{font-weight:700}button,.btn{display:inline-block;background:#087b9b;color:white;border:0;border-radius:8px;padding:11px 16px;margin:8px 5px 5px 0}.gold{background:#c99b3b}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #e5edef}.badge{background:#e6f4f7;padding:5px 9px;border-radius:12px}.workspace{display:grid;grid-template-columns:1fr 1fr;gap:18px}.viewer{max-height:650px;overflow:auto}.viewer img{width:100%;height:auto;display:block;margin:10px 0 18px;border-radius:8px}.viewer iframe{width:100%;height:560px;border:1px solid #dce8ec;border-radius:8px;margin:10px 0 18px}.exam-file{margin-bottom:18px}.filebar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.filebar b{margin-right:auto}.editor textarea{min-height:430px}.muted{color:#657f89}.notice{padding:12px;background:#fff7df;border-left:4px solid #c99b3b;margin:12px 0}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.cards .card b{display:block;font-size:28px;color:#087b9b}
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
@media(max-width:900px){.login-approved{grid-template-columns:1fr}.login-visual{min-height:42vh;padding:28px 8%;background-size:191% 100%}.login-copy h1{font-size:30px}.login-copy p{font-size:16px}.login-panel{padding:38px 22px 70px}.login-footer{left:0;font-size:10px}.shell,.workspace,.grid,.cards{grid-template-columns:1fr}.shell aside{position:relative}main{padding:18px;max-width:100%;overflow:hidden}.card{padding:16px}table{display:block;overflow-x:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}.viewer{max-height:70vh}.viewer iframe{height:60vh}.editor textarea{min-height:300px}.filebar .btn{padding:9px 12px}}@media(max-width:520px){.login-visual{min-height:34vh}.login-panel{padding:28px 16px 64px}.login-card h2{font-size:25px}.login-card input,.login-card .submit{height:52px}aside{padding:20px 16px}aside a{display:inline-block;margin:12px 14px 4px 0}.brand{font-size:22px}main{padding:14px}.card{border-radius:12px;padding:14px}button,.btn{max-width:100%}.workspace{gap:10px}}"""

def page(body,title="MALIBUB"):
 msgs="".join(f'<div class="notice">{html_escape(m)}</div>' for m in __import__("flask").get_flashed_messages())
 body=msgs+body
 nav=""
 if session.get("uid"):
  nav=f'''<aside><div class="brand">MALIBUB<span>Imaginologia</span><small>PRECISÃO • CONFIANÇA • AGILIDADE</small></div><a href="/dashboard">Painel</a>{'<a href="/new">Novo Exame</a>' if session.get('role')=='Clinica' else ''}{'<a href="/finance">Financeiro</a><a href="/admin/usuarios">Administração</a>' if session.get('role')=='Radiologista' else ''}<a href="/minha-conta">Minha conta</a><form method="post" action="/logout" style="margin:0">{csrf_field()}<button type="submit" style="width:100%;text-align:left;background:none;border:0;color:inherit;padding:12px 14px;cursor:pointer;font:inherit">Sair</button></form></aside>'''
  return f'<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{CSS}</style><div class="shell">{nav}<main>{body}</main></div></html>'
 return f'<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{CSS}</style>{body}</html>'

_initialized=False
@app.before_request
def init():
 global _initialized
 if _initialized: return
 if object_storage_enabled():
  ensure_r2_browser_cors()
  ensure_r2_retention_lifecycle()
 db.create_all()
 if db.engine.dialect.name=="postgresql":
  try:
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS logo VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS logo_name VARCHAR(255)"))
   db.session.execute(db.text("ALTER TABLE exam_file ADD COLUMN IF NOT EXISTS scan_status VARCHAR(20) DEFAULT 'PENDENTE'"))
   db.session.execute(db.text("ALTER TABLE exam_file ADD COLUMN IF NOT EXISTS scan_detail VARCHAR(255)"))
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
 <button class="submit" type="submit">Entrar</button></form><div class="foot">Acesso exclusivo para clínicas e radiologista.</div></div></section>
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
 rows="".join("<tr><td>"+str(html_escape(x.exam_type))+"</td><td>R$ "+format(x.amount,".2f")+"</td><td><form method='post' action='/admin/usuarios/"+str(u.id)+"/precos/"+str(x.id)+"/excluir' style='margin:0' onsubmit=\"return confirm('Excluir este preço contratado?')\">"+csrf_field()+"<button type='submit'>Excluir</button></form></td></tr>" for x in prices)
 body=f"""<h1>Tabela de preços — {html_escape(u.name)}</h1><div class='card'><p class='muted'>Cadastre o valor contratado por tipo de exame. O sistema usará este preço automaticamente ao laudar.</p><form method='post'>{csrf_field()}<label>Tipo de exame<input name='exam_type' maxlength='100' placeholder='Ex.: Panorâmica' required></label><label>Valor contratado (R$)<input type='number' name='amount' min='0.01' step='0.01' required></label><button class='gold' type='submit'>Salvar preço</button></form></div><div class='card'><h2>Preços cadastrados</h2><table><tr><th>Tipo de exame</th><th>Valor</th><th>Ação</th></tr>{rows or '<tr><td colspan=3>Nenhum preço cadastrado.</td></tr>'}</table></div>"""
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
 for e in exams:
  blocked=ExamFile.query.filter(ExamFile.exam_id==e.id,ExamFile.scan_status.in_(["SUSPEITO","INFECTADO"])).first()
  if session["role"]=="Clinica" and blocked:
   action="<span style='display:inline-block;background:#b42318;color:white;font-weight:800;padding:9px 12px;border-radius:8px'>SUSPEITO/INFECTADO</span>"
  else:
   action=(f'<a class="btn" href="/report/{e.id}">Laudar</a>' if session["role"]=="Radiologista" and e.status!="Liberado" else (f'<a class="btn" href="/result/{e.id}">Resultado</a>' if e.status=="Liberado" else ""))
  rows+=f"<tr><td>{html_escape(e.protocol)}</td><td>{html_escape(e.patient)}</td><td>{html_escape(e.exam_type)}</td><td><span class='badge'>{html_escape(e.status)}</span></td><td>{action}</td></tr>"
 body=f'''<h1>Painel {'da Clínica' if session["role"]=="Clinica" else 'da Radiologista'}</h1><p>Olá, {html_escape(session["name"])}.</p>{'<a class="btn gold" href="/new">+ Novo Exame</a><a class="btn" href="/modelo-laudo">Modelo de laudo</a>' if session["role"]=="Clinica" else ''}<div class="card"><h2>Exames</h2><table><tr><th>Protocolo</th><th>Paciente</th><th>Exame</th><th>Status</th><th>Ação</th></tr>{rows or '<tr><td colspan=5>Nenhum exame.</td></tr>'}</table></div>'''
 return page(body)

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
    flash("SUSPEITO/INFECTADO — a logomarca foi bloqueada e não foi armazenada.")
    return redirect("/modelo-laudo")
   if scan_status=="ERRO" and MALWARE_SCAN_REQUIRED:
    flash("A varredura de segurança está indisponível. O arquivo não foi armazenado.")
    return redirect("/modelo-laudo")
   logo_stored="logo_"+str(u.id)+"_"+uuid.uuid4().hex+logo_ext
   store_upload(logo,logo_stored,logo.mimetype)
   old_logo=u.logo
   u.logo=logo_stored; u.logo_name=logo_name
   db.session.commit()
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
    flash("SUSPEITO/INFECTADO — o modelo de laudo foi bloqueado e não foi armazenado.")
    return redirect("/modelo-laudo")
   if scan_status=="ERRO" and MALWARE_SCAN_REQUIRED:
    flash("A varredura de segurança está indisponível. O arquivo não foi armazenado.")
    return redirect("/modelo-laudo")
   stored="modelo_"+str(u.id)+"_"+uuid.uuid4().hex+ext
   store_upload(file,stored,file.mimetype)
   old_model=u.report_model
   u.report_model=stored; u.report_model_name=name; db.session.commit()
   if old_model:
    try: storage_delete(old_model)
    except Exception: pass
   flash("Modelo personalizado da clínica salvo após varredura de segurança.")
  return redirect("/modelo-laudo")
 current=(f"<p><b>Modelo atual:</b> {html_escape(u.report_model_name or '')}</p><a class='btn' href='/modelo-laudo/arquivo' target='_blank'>Visualizar modelo</a>" if u.report_model else "<div class='notice'>Nenhum modelo personalizado cadastrado.</div>")
 body=f"""<h1>Identidade visual / Modelo de laudo</h1><div class='card'><p>Cadastre a identidade visual da clínica e o modelo personalizado que servirá de referência para os laudos.</p>{("<p><b>Logomarca atual:</b> "+html_escape(u.logo_name or "")+"</p>") if u.logo else "<div class='notice'>Nenhuma logomarca cadastrada.</div>"}{current}<form method='post' enctype='multipart/form-data'>{csrf_field()}<label>Logomarca da clínica (JPG ou PNG)<input type='file' name='logo' accept='.jpg,.jpeg,.png,image/jpeg,image/png'></label><label>Modelo personalizado (PDF, DOCX, JPG ou PNG)<input type='file' name='report_model' accept='.pdf,.docx,.jpg,.jpeg,.png,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,image/jpeg,image/png'></label><div class='grid'><label>Margem superior do conteúdo (mm)<input type='number' name='report_top_mm' min='20' max='120' value='{u.report_top_mm or 72}'></label><label>Margem inferior (mm)<input type='number' name='report_bottom_mm' min='15' max='100' value='{u.report_bottom_mm or 42}'></label></div><p class='muted'>Ajuste estes valores quando o papel timbrado tiver cabeçalho ou rodapé maiores.</p><button class='gold' type='submit'>Salvar modelo e posicionamento</button></form></div>"""
 return page(body)

@app.route("/modelo-laudo/arquivo")
def report_model_file():
 if not session.get("uid"): return redirect("/")
 uid=session.get("uid")
 if session.get("role")=="Radiologista":
  eid=request.args.get("exam",type=int)
  if not eid: return redirect("/dashboard")
  e=Exam.query.get_or_404(eid); uid=e.clinic_id
 elif session.get("role")!="Clinica":
  return redirect("/")
 u=User.query.get_or_404(uid)
 if not u.report_model: return redirect("/dashboard")
 if not storage_exists(u.report_model):
  flash("O modelo de laudo não está disponível no armazenamento atual. Envie o modelo novamente.")
  return redirect("/modelo-laudo" if session.get("role")=="Clinica" else "/dashboard")
 return storage_response(u.report_model,u.report_model_name,False)

@app.post("/new/direct-upload-url")
def direct_upload_url():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 if not object_storage_enabled(): return {"error":"storage_unavailable"},503
 data=request.get_json(silent=True) or {}
 name=secure_filename(str(data.get("name","")))
 content_type=str(data.get("content_type") or "application/octet-stream")[:120]
 if not name or Path(name).suffix.lower() not in {".jpg",".jpeg",".png",".pdf",".dcm",".zip",".rar"}: return {"error":"invalid_file"},400
 key=uuid.uuid4().hex+"_"+name
 url=r2_client().generate_presigned_url("put_object",Params={"Bucket":R2_BUCKET,"Key":key,"ContentType":content_type},ExpiresIn=900)
 return {"key":key,"url":url,"content_type":content_type},200

@app.post("/new/direct-finalize")
def direct_upload_finalize():
 if session.get("role")!="Clinica": return {"error":"unauthorized"},403
 data=request.get_json(silent=True) or {}; files=data.get("files") or []
 patient=str(data.get("patient","")).strip()[:120]; dentist=str(data.get("dentist","")).strip()[:120]; exam_type=str(data.get("exam_type","")).strip()[:80]
 if not files or not patient or not dentist or not exam_type: return {"error":"required_fields"},400
 verified=[]
 try:
  for item in files:
   key=str(item.get("key","")); name=secure_filename(str(item.get("name","")))
   if not key or not name or not key.endswith("_"+name): raise ValueError("invalid upload")
   r2_client().head_object(Bucket=R2_BUCKET,Key=key); verified.append((key,name))
  e=Exam(protocol="MB"+datetime.now().strftime("%y%m%d%H%M%S"),patient=patient,sex=str(data.get("sex","Não informado")).strip(),birth=str(data.get("birth",""))[:20],dentist=dentist,exam_date=str(data.get("exam_date",""))[:20],exam_type=exam_type,observation=str(data.get("observation","")).strip()[:500],clinic_id=session["uid"],status="Aguardando laudo",due_at=datetime.utcnow()+timedelta(hours=24))
  db.session.add(e); db.session.flush()
  for key,name in verified: db.session.add(ExamFile(exam_id=e.id,name=name,stored=key,scan_status="NAO_VERIFICADO",scan_detail="Verificação antivírus opcional pela radiologista."))
  db.session.commit(); return {"status":"ok","redirect":"/dashboard"},200
 except Exception as exc:
  db.session.rollback(); app.logger.error("direct_upload_finalize_failed error_type=%s",type(exc).__name__); return {"error":"finalize_failed"},500

@app.route("/new",methods=["GET","POST"])
def new():
 if session.get("role")!="Clinica": return redirect("/dashboard")
 allowed_ext={".jpg",".jpeg",".png",".pdf",".dcm",".zip",".rar"}
 if request.method=="POST":
  incoming=[f for f in request.files.getlist("files") if f and f.filename]
  if not incoming:
   flash("Anexe ao menos um arquivo do exame antes de enviar.")
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
  if not patient or not dentist or not exam_type:
   flash("Preencha os dados obrigatórios do exame.")
   return redirect("/new")
  e=Exam(protocol="MB"+datetime.now().strftime("%y%m%d%H%M%S"),patient=patient,sex=sex,birth=request.form.get("birth",""),dentist=dentist,exam_date=request.form.get("exam_date",""),exam_type=exam_type,observation=request.form.get("observation","").strip()[:500],clinic_id=session["uid"],status="Aguardando laudo",due_at=datetime.utcnow()+timedelta(hours=24))
  db.session.add(e); db.session.flush()
  uploaded=[]
  try:
   for f in incoming:
    name=secure_filename(f.filename)
    scan_status,scan_detail="NAO_VERIFICADO","Varredura antivírus desativada no fluxo de upload."
    stored=uuid.uuid4().hex+"_"+name
    store_upload(f,stored,f.mimetype)
    uploaded.append(stored)
    db.session.add(ExamFile(exam_id=e.id,name=name,stored=stored,scan_status=scan_status,scan_detail=scan_detail))
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
 body=f'''<h1>Novo Exame</h1><div class="card"><form id="exam-form" method="post" enctype="multipart/form-data">{csrf_field()}<div class="grid"><label>Nome do paciente<input name="patient" required></label><label>Sexo<select name="sex"><option>Feminino</option><option>Masculino</option><option>Não informado</option></select></label><label>Data de nascimento<input type="date" name="birth" required></label><label>Dentista solicitante<input name="dentist" required></label><label>Data do exame<input type="date" name="exam_date" required></label><label>Tipo de exame<select name="exam_type"><option>Tomografia computadorizada</option><option>Panorâmica</option><option>Documentação</option><option>Tomografia Endo</option></select></label></div><label>Observação / motivo<textarea name="observation" maxlength="500"></textarea></label><label>Imagens e arquivos<input id="exam-files" type="file" name="files" multiple accept=".jpg,.jpeg,.png,.pdf,.dcm,.zip,.rar"></label><div id="upload-progress" class="notice" style="display:none"></div><button id="send-exam" class="gold">Enviar exame</button></form></div>
<script>
(function(){{
 const form=document.getElementById("exam-form"), input=document.getElementById("exam-files"), box=document.getElementById("upload-progress"), btn=document.getElementById("send-exam");
 if(!form||!input) return;
 const csrf=form.querySelector("[name=_csrf_token]").value;
 form.addEventListener("submit",async function(ev){{
  if(!window.fetch||!input.files.length) return;
  ev.preventDefault(); btn.disabled=true; box.style.display="block";
  try{{
   const uploaded=[];
   for(let i=0;i<input.files.length;i++){{
    const file=input.files[i];
    box.textContent="Enviando arquivo "+(i+1)+" de "+input.files.length+"...";
    const a=await fetch("/new/direct-upload-url",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify({{name:file.name,content_type:file.type||"application/octet-stream"}})}});
    if(!a.ok) throw new Error("auth");
    const s=await a.json();
    const p=await fetch(s.url,{{method:"PUT",headers:{{"Content-Type":s.content_type}},body:file}});
    if(!p.ok) throw new Error("put");
    uploaded.push({{key:s.key,name:file.name}});
   }}
   box.textContent="Finalizando envio...";
   const fd=new FormData(form), payload={{files:uploaded}};
   ["patient","sex","birth","dentist","exam_date","exam_type","observation"].forEach(k=>payload[k]=fd.get(k)||"");
   const d=await fetch("/new/direct-finalize",{{method:"POST",headers:{{"Content-Type":"application/json","X-CSRF-Token":csrf}},body:JSON.stringify(payload)}});
   if(!d.ok) throw new Error("finalize");
   const r=await d.json(); location.href=r.redirect||"/dashboard";
  }}catch(e){{
   box.textContent="Usando modo compatível de envio...";
   btn.disabled=false; form.submit();
  }}
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
   stored=uuid.uuid4().hex+ext
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

@app.route("/report/<int:eid>",methods=["GET","POST"])
def report(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid)
 if ExamFile.query.filter(ExamFile.exam_id==e.id,ExamFile.kind=="bloqueado",ExamFile.scan_status.in_(["SUSPEITO","INFECTADO"]),ExamFile.uploaded_by!=session.get("name")).first():
  flash("Exame bloqueado pela segurança. Arquivo suspeito/infectado não foi disponibilizado.")
  return redirect("/dashboard")
 files=ExamFile.query.filter_by(exam_id=e.id).filter((ExamFile.kind=="entrada") | (ExamFile.kind==None)).all()
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
 ready_html="".join((f"<div class='exam-file'><div class='filebar'><b>{html_escape(f.name)}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}'>" if f.name.lower().endswith(('.jpg','.jpeg')) else f"<iframe src='/exam-file/{f.id}'></iframe>") + "</div>") for f in ready_files)
 clinic=User.query.get(e.clinic_id); price=ClinicPrice.query.filter_by(clinic_id=e.clinic_id,exam_type=e.exam_type,active=True).first(); suggested_amount=(price.amount if price else None); model_link=(f"<a class='btn' href='/modelo-laudo/arquivo?exam={e.id}' target='_blank'>Ver modelo de laudo da clínica</a>" if clinic and clinic.report_model else "<span class='muted'>Clínica sem modelo de laudo cadastrado.</span>")
 body=f'''<h1>Ambiente da Radiologista — {html_escape(e.protocol)}</h1><div style="margin-bottom:12px">{model_link}</div><div class="card"><b>{html_escape(e.patient)}</b> · {html_escape(e.exam_type)}<br><span class="muted">{html_escape(e.observation or 'Sem observação clínica.')}</span></div><div class="workspace"><section class="card viewer"><h2>Imagens / arquivos</h2>{imgs or 'Nenhum anexo.'}<hr style="margin:24px 0;border:0;border-top:1px solid #dce8ec"><h2>Exame pronto / Templates</h2><p class="muted">Anexe o exame final produzido pela radiologista em JPG/JPEG e/ou PDF. Os arquivos ficarão vinculados a este exame.</p><form method="post" action="/report/{e.id}/exame-pronto" enctype="multipart/form-data">{csrf_field()}<input type="file" name="finished_files" accept=".jpg,.jpeg,.pdf,image/jpeg,application/pdf" multiple required><button class="gold" type="submit">Anexar exame pronto</button></form>{ready_html or '<div class="notice">Nenhum template/exame pronto anexado ainda.</div>'}</section><section class="card editor"><h2>Laudo escrito</h2><form method="post">{csrf_field()}<textarea name="report" placeholder="Digite o laudo..." required>{html_escape(e.report or '')}</textarea><label>Valor do laudo (R$)<input type="number" min="0.01" step="0.01" name="amount" value="{format(suggested_amount,'.2f') if suggested_amount is not None else ''}" placeholder="0,00" required></label><p class="muted">{'Valor contratado desta clínica para este tipo de exame, preenchido automaticamente.' if suggested_amount is not None else 'Sem preço contratado para este tipo de exame. Informe o valor antes de liberar.'} O valor será usado no Financeiro e no relatório de cobrança da clínica.</p><div class="editor-actions"><button type="button" onclick="localStorage.setItem('malibub_draft_{e.id}',document.querySelector('[name=report]').value);this.textContent='Rascunho salvo ✓'">Salvar rascunho</button><button type="submit" formaction="/report/{e.id}/preview-pdf" formmethod="post" formtarget="_blank">Visualizar laudo</button><button class="gold" type="submit">Finalizar e liberar</button></div></form><script>const ta=document.querySelector('[name=report]');if(!ta.value)ta.value=localStorage.getItem('malibub_draft_{e.id}')||'';</script></section></div>'''
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
  signed=e.signed_at.strftime("%d/%m/%Y %H:%M") if e.signed_at else (e.released_at.strftime("%d/%m/%Y %H:%M") if e.released_at else "")
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
 if not story and not has_pdf_model: story=[Paragraph("MALIBUB",title),Paragraph("Imaginologia Odontológica",ParagraphStyle("s",parent=styles["Normal"],alignment=TA_CENTER,textColor=teal,fontSize=10)),Spacer(1,6*mm)]
 if not has_pdf_model:
  data=[["Protocolo",escape(e.protocol or "")],["Paciente",escape(e.patient or "")],["Exame",escape(e.exam_type or "")],["Dentista solicitante",escape(e.dentist or "")],["Data do exame",escape(br_date(e.exam_date))]]
  t=Table(data,colWidths=[42*mm,120*mm]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.4,colors.HexColor("#DCE8EC")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F1F6F7")),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("PADDING",(0,0),(-1,-1),6)])); story += [t,Spacer(1,7*mm),Paragraph("LAUDO RADIOLÓGICO",ParagraphStyle("h",parent=title,alignment=0,fontSize=12,textColor=navy)),Spacer(1,2*mm)]
 if not has_pdf_model:
  for line in (e.report or "").splitlines(): story.append(Paragraph(escape(line) or "&nbsp;",body))
 signer=escape(e.signed_by or "Dra. Marina"); signed=e.signed_at.strftime("%d/%m/%Y %H:%M") if e.signed_at else (e.released_at.strftime("%d/%m/%Y %H:%M") if e.released_at else "")
 if not has_pdf_model:
  story += [Spacer(1,12*mm),Table([[""]],colWidths=[70*mm],style=TableStyle([("LINEABOVE",(0,0),(-1,-1),.6,navy)])),Paragraph(f"<b>{signer}</b>",ParagraphStyle("sig",parent=body,alignment=TA_CENTER,textColor=navy)),Paragraph("Radiologista responsável",ParagraphStyle("sig2",parent=styles["Normal"],alignment=TA_CENTER,fontSize=8,textColor=colors.HexColor("#657F89"))),Spacer(1,3*mm),Paragraph(f"Assinado eletronicamente em {escape(signed)}",ParagraphStyle("f",parent=styles["Normal"],fontSize=8,textColor=colors.HexColor("#657F89"))),Paragraph(f"Validação MALIBUB · Protocolo {escape(e.protocol or '')}",ParagraphStyle("f3",parent=styles["Normal"],fontSize=7.5,textColor=colors.HexColor("#657F89"))),Spacer(1,2*mm),Paragraph((escape(clinic.name)+" · MALIBUB Imaginologia Odontológica") if clinic else "MALIBUB Imaginologia Odontológica",ParagraphStyle("f2",parent=styles["Normal"],fontSize=8,textColor=gold))]
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
    cv.setFont("Helvetica",8); cv.drawString(22*mm,height-27*mm,f"Paciente: {e.patient}")
    cv.line(22*mm,height-31*mm,width-22*mm,height-31*mm)
    y=height-40*mm; cv.setFont("Helvetica",9)
    while line_index<len(report_lines) and y>25*mm:
     cv.drawString(22*mm,y,report_lines[line_index][:max_chars]); line_index+=1; y-=4.4*mm
    cv.setFont("Helvetica",7.5); cv.setFillColor(colors.HexColor("#52666E"))
    cv.drawCentredString(width/2,10*mm,f"Assinado eletronicamente por {e.signed_by or 'Dra. Marina'}")
    cv.drawCentredString(width/2,6.5*mm,f"Data: {signed} · Protocolo {e.protocol or ''}")
    cv.save(); extra.seek(0); final_writer.add_page(PdfReader(extra).pages[0])
   merged=io.BytesIO(); final_writer.write(merged); merged.seek(0); buf=merged
  except Exception:
   return "Não foi possível gerar o PDF personalizado. Verifique o modelo de laudo cadastrado.",500
 response=send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"{e.protocol}_laudo.pdf")
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
 signed=(e.signed_at.strftime("%d/%m/%Y %H:%M") if e.signed_at else "")
 body=f'''<h1>Resultado — {html_escape(e.protocol)}</h1><div class="card"><div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap"><div><h2 style="margin:0 0 6px">{html_escape(e.patient)}</h2><div class="muted">{html_escape(e.exam_type)} · {html_escape(e.dentist or 'Dentista não informado')}</div></div><span class="badge">{html_escape(e.status)}</span></div><hr><h3>Laudo radiológico</h3><div style="white-space:pre-wrap;min-height:220px;line-height:1.6">{html_escape(e.report or 'Laudo não informado.')}</div><div style="margin-top:22px;padding-top:16px;border-top:1px solid #dce8ec"><b>{html_escape(e.signed_by or 'Dra. Marina')}</b><br><span class="muted">Radiologista responsável · Assinado eletronicamente {signed}</span></div><hr><a class="btn gold" href="/result/{e.id}/pdf">Baixar laudo assinado em PDF</a><button onclick="window.print()">Imprimir</button></div><section class="card viewer"><h2>Exame pronto / Templates</h2><p class="muted">Arquivos finais disponibilizados pela radiologista.</p>{ready_html or '<div class="notice">Nenhum arquivo final foi anexado.</div>'}</section>'''
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
