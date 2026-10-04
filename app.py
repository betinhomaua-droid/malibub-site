from flask import Flask, request, redirect, url_for, session, flash, render_template_string, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from pathlib import Path
import os, uuid, io

app=Flask(__name__)
app.config["SECRET_KEY"]=os.getenv("SECRET_KEY","malibub-homologacao")
app.config["SQLALCHEMY_DATABASE_URI"]=os.getenv("DATABASE_URL","sqlite:///malibub.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config["MAX_CONTENT_LENGTH"]=200*1024*1024
app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
db=SQLAlchemy(app)
UPLOAD=Path(app.instance_path)/"uploads"; UPLOAD.mkdir(parents=True,exist_ok=True)

@app.route("/assets/<path:filename>")
def assets(filename):
 return send_from_directory(Path(app.root_path)/"assets", filename)

class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(100)); email=db.Column(db.String(120),unique=True); password=db.Column(db.String(255)); role=db.Column(db.String(30)); report_model=db.Column(db.String(255)); report_model_name=db.Column(db.String(255))
class Exam(db.Model):
 id=db.Column(db.Integer,primary_key=True); protocol=db.Column(db.String(30),unique=True); patient=db.Column(db.String(120)); sex=db.Column(db.String(20)); birth=db.Column(db.String(20)); dentist=db.Column(db.String(120)); exam_date=db.Column(db.String(20)); exam_type=db.Column(db.String(100)); observation=db.Column(db.String(500)); status=db.Column(db.String(50),default="Enviado"); clinic_id=db.Column(db.Integer); due_at=db.Column(db.DateTime); report=db.Column(db.Text,default=""); released_at=db.Column(db.DateTime); signed_by=db.Column(db.String(120)); signed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class ExamFile(db.Model):
 id=db.Column(db.Integer,primary_key=True); exam_id=db.Column(db.Integer); name=db.Column(db.String(255)); stored=db.Column(db.String(255)); kind=db.Column(db.String(30),default="entrada"); uploaded_by=db.Column(db.String(100))
class Finance(db.Model):
 id=db.Column(db.Integer,primary_key=True); date=db.Column(db.Date,default=datetime.utcnow().date); description=db.Column(db.String(200)); kind=db.Column(db.String(20)); amount=db.Column(db.Float,default=0)

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
@media(max-width:900px){.login-approved{grid-template-columns:1fr}.login-visual{min-height:42vh;padding:28px 8%}.login-copy h1{font-size:30px}.login-copy p{font-size:16px}.login-panel{padding:38px 22px 70px}.login-footer{font-size:10px}.shell,.workspace,.grid,.cards{grid-template-columns:1fr}.shell aside{position:relative}}"""

def page(body,title="MALIBUB"):
 nav=""
 if session.get("uid"):
  nav=f'''<aside><div class="brand">MALIBUB<span>Imaginologia</span><small>PRECISÃO • CONFIANÇA • AGILIDADE</small></div><a href="/dashboard">Painel</a>{'<a href="/new">Novo Exame</a>' if session.get('role')=='Clinica' else ''}{'<a href="/finance">Financeiro</a>' if session.get('role')=='Radiologista' else ''}<a href="/logout">Sair</a></aside>'''
  return f'<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{CSS}</style><div class="shell">{nav}<main>{body}</main></div></html>'
 return f'<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{CSS}</style>{body}</html>'

@app.before_request
def init():
 db.create_all()
 try:
  cols=[r[1] for r in db.session.execute(db.text("PRAGMA table_info(exam)")).fetchall()]
  if "signed_by" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN signed_by VARCHAR(120)"))
  if "signed_at" not in cols: db.session.execute(db.text("ALTER TABLE exam ADD COLUMN signed_at DATETIME"))
  db.session.commit()
 except Exception: db.session.rollback()
 if not User.query.first():
  db.session.add(User(name="Clínica Demo",email="clinica@malibub.com",password=generate_password_hash("Malibub2026"),role="Clinica"))
  db.session.add(User(name="Dra. Marina",email="radiologista@malibub.com",password=generate_password_hash("Malibub2026"),role="Radiologista")); db.session.commit()

@app.route("/",methods=["GET","POST"])
def login():
 if request.method=="POST":
  u=User.query.filter_by(email=request.form["email"].lower()).first()
  if u and check_password_hash(u.password,request.form["password"]):
   session.update(uid=u.id,role=u.role,name=u.name); return redirect("/dashboard")
  flash("E-mail ou senha inválidos.")
 msgs="".join(f'<div class="login-flash">{m}</div>' for m in __import__("flask").get_flashed_messages())
 body=f'''<div class="login-approved">
 <section class="login-visual" aria-label="MALIBUB Imaginologia Odontológica"><span class="footer-mask" aria-hidden="true"></span></section>
 <section class="login-panel"><div class="login-card">{msgs}<h2>Acesse sua conta</h2><p class="sub">Entre para enviar ou acessar seus exames.</p>
 <form method="post"><label for="email">Email</label><input id="email" type="email" name="email" placeholder="voce@clinica.com" required autocomplete="username">
 <div class="pass-wrap"><label for="pwd">Senha</label><input id="pwd" type="password" name="password" placeholder="Sua senha" required autocomplete="current-password"><button class="eye" type="button" aria-label="Mostrar ou ocultar senha" onclick="var p=document.getElementById('pwd');p.type=p.type==='password'?'text':'password';this.textContent=p.type==='password'?'◉':'○'">◉</button></div>
 <button class="submit" type="submit">Entrar</button></form><div class="foot">Acesso exclusivo para clínicas e radiologista.</div></div></section>
<div class="login-footer">© 2026 Malibub Radiologia &nbsp; Todos os Direitos Reservados</div></div>'''
 return page(body,"Entrar · MALIBUB")

@app.route("/dashboard")
def dashboard():
 if not session.get("uid"): return redirect("/")
 q=Exam.query
 if session["role"]=="Clinica": exams=q.filter_by(clinic_id=session["uid"]).order_by(Exam.created_at.desc()).all()
 else: exams=q.order_by(Exam.created_at.desc()).all()
 rows=""
 for e in exams:
  action=f'<a class="btn" href="/report/{e.id}">Laudar</a>' if session["role"]=="Radiologista" and e.status!="Liberado" else (f'<a class="btn" href="/result/{e.id}">Resultado</a>' if e.status=="Liberado" else "")
  rows+=f"<tr><td>{e.protocol}</td><td>{e.patient}</td><td>{e.exam_type}</td><td><span class='badge'>{e.status}</span></td><td>{action}</td></tr>"
 body=f'''<h1>Painel {'da Clínica' if session["role"]=="Clinica" else 'da Radiologista'}</h1><p>Olá, {session["name"]}.</p>{'<a class="btn gold" href="/new">+ Novo Exame</a><a class="btn" href="/modelo-laudo">Modelo de laudo</a>' if session["role"]=="Clinica" else ''}<div class="card"><h2>Exames</h2><table><tr><th>Protocolo</th><th>Paciente</th><th>Exame</th><th>Status</th><th>Ação</th></tr>{rows or '<tr><td colspan=5>Nenhum exame.</td></tr>'}</table></div>'''
 return page(body)

@app.route("/modelo-laudo",methods=["GET","POST"])
def report_model():
 if session.get("role")!="Clinica": return redirect("/dashboard")
 u=User.query.get_or_404(session["uid"])
 if request.method=="POST":
  file=request.files.get("report_model")
  if file and file.filename:
   name=secure_filename(file.filename); ext=Path(name).suffix.lower()
   if ext not in {".pdf",".jpg",".jpeg",".png"}: flash("Use PDF, JPG ou PNG."); return redirect("/modelo-laudo")
   stored="modelo_"+str(u.id)+"_"+uuid.uuid4().hex+ext; file.save(UPLOAD/stored)
   u.report_model=stored; u.report_model_name=name; db.session.commit(); flash("Modelo personalizado da clínica salvo.")
  return redirect("/modelo-laudo")
 current=(f"<p><b>Modelo atual:</b> {u.report_model_name}</p><a class='btn' href='/modelo-laudo/arquivo' target='_blank'>Visualizar modelo</a>" if u.report_model else "<div class='notice'>Nenhum modelo personalizado cadastrado.</div>")
 body=f"""<h1>Modelo de laudo da clínica</h1><div class='card'><p>Envie a página/modelo personalizado que deverá servir de referência para os laudos desta clínica.</p>{current}<form method='post' enctype='multipart/form-data'><label>Modelo personalizado (PDF, JPG ou PNG)<input type='file' name='report_model' accept='.pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png' required></label><button class='gold' type='submit'>Salvar modelo da clínica</button></form></div>"""
 return page(body)

@app.route("/modelo-laudo/arquivo")
def report_model_file():
 if not session.get("uid"): return redirect("/")
 uid=session.get("uid")
 if session.get("role")=="Radiologista":
  eid=request.args.get("exam",type=int); e=Exam.query.get_or_404(eid); uid=e.clinic_id
 u=User.query.get_or_404(uid)
 if not u.report_model: return redirect("/dashboard")
 return send_from_directory(UPLOAD,u.report_model,download_name=u.report_model_name,as_attachment=False)

@app.route("/new",methods=["GET","POST"])
def new():
 if session.get("role")!="Clinica": return redirect("/dashboard")
 if request.method=="POST":
  e=Exam(protocol="MB"+datetime.now().strftime("%y%m%d%H%M%S"),patient=request.form["patient"],sex=request.form["sex"],birth=request.form["birth"],dentist=request.form["dentist"],exam_date=request.form["exam_date"],exam_type=request.form["exam_type"],observation=request.form.get("observation","")[:500],clinic_id=session["uid"],status="Aguardando laudo",due_at=datetime.utcnow()+timedelta(hours=24)); db.session.add(e); db.session.commit()
  for f in request.files.getlist("files"):
   if f and f.filename:
    name=secure_filename(f.filename); stored=uuid.uuid4().hex+"_"+name; f.save(UPLOAD/stored); db.session.add(ExamFile(exam_id=e.id,name=name,stored=stored))
  db.session.commit(); return redirect("/dashboard")
 body='''<h1>Novo Exame</h1><div class="card"><form method="post" enctype="multipart/form-data"><div class="grid"><label>Nome do paciente<input name="patient" required></label><label>Sexo<select name="sex"><option>Feminino</option><option>Masculino</option><option>Não informado</option></select></label><label>Data de nascimento<input type="date" name="birth" required></label><label>Dentista solicitante<input name="dentist" required></label><label>Data do exame<input type="date" name="exam_date" required></label><label>Tipo de exame<select name="exam_type"><option>Tomografia computadorizada</option><option>Panorâmica</option><option>Documentação</option><option>Tomografia Endo</option></select></label></div><label>Observação / motivo<textarea name="observation" maxlength="500"></textarea></label><label>Imagens e arquivos<input type="file" name="files" multiple accept=".jpg,.jpeg,.png,.pdf,.dcm,.zip,.rar"></label><button class="gold">Enviar exame</button></form></div>'''
 return page(body)

@app.route("/exam-file/<int:fid>")
def exam_file(fid):
 if not session.get("uid"): return redirect("/")
 f=ExamFile.query.get_or_404(fid); e=Exam.query.get_or_404(f.exam_id)
 if session.get("role")=="Clinica" and e.clinic_id!=session.get("uid"): return redirect("/dashboard")
 return send_from_directory(UPLOAD,f.stored,as_attachment=request.args.get("download")=="1",download_name=f.name)

@app.route("/report/<int:eid>/exame-pronto",methods=["POST"])
def upload_ready_exam(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid); saved=0
 for file in request.files.getlist("finished_files"):
  if not file or not file.filename: continue
  name=secure_filename(file.filename); ext=Path(name).suffix.lower()
  if ext not in {".jpg",".jpeg",".pdf"}: continue
  stored=uuid.uuid4().hex+ext; file.save(UPLOAD/stored)
  db.session.add(ExamFile(exam_id=e.id,name=name,stored=stored,kind="exame_pronto",uploaded_by=session.get("name"))); saved+=1
 db.session.commit(); flash(f"{saved} arquivo(s) do exame pronto anexado(s)." if saved else "Selecione JPG ou PDF.")
 return redirect(url_for("report",eid=e.id))

@app.route("/report/<int:eid>",methods=["GET","POST"])
def report(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid); files=ExamFile.query.filter_by(exam_id=e.id).filter((ExamFile.kind=="entrada") | (ExamFile.kind==None)).all(); ready_files=ExamFile.query.filter_by(exam_id=e.id,kind="exame_pronto").all()
 if request.method=="POST":
  e.report=request.form["report"]; e.status="Liberado"; e.released_at=datetime.utcnow(); e.signed_by=session.get("name") or "Dra. Marina"; e.signed_at=datetime.utcnow(); db.session.add(Finance(description=f"Laudo {e.protocol}",kind="Entrada",amount=float(request.form.get("amount") or 0))); db.session.commit(); return redirect("/dashboard")
 imgs="".join((f"<div class='exam-file'><div class='filebar'><b>{f.name}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{f.name}'>" if f.name.lower().endswith(('.jpg','.jpeg','.png','.webp')) else (f"<iframe src='/exam-file/{f.id}' title='{f.name}'></iframe>" if f.name.lower().endswith('.pdf') else "<div class='notice'>Pré-visualização indisponível para este formato. Use Abrir ou Baixar.</div>")) + "</div>") for f in files)
 ready_html="".join((f"<div class='exam-file'><div class='filebar'><b>{f.name}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}'>" if f.name.lower().endswith(('.jpg','.jpeg')) else f"<iframe src='/exam-file/{f.id}'></iframe>") + "</div>") for f in ready_files)
 clinic=User.query.get(e.clinic_id); model_link=(f"<a class='btn' href='/modelo-laudo/arquivo?exam={e.id}' target='_blank'>Ver modelo de laudo da clínica</a>" if clinic and clinic.report_model else "<span class='muted'>Clínica sem modelo de laudo cadastrado.</span>")
 body=f'''<h1>Ambiente da Radiologista — {e.protocol}</h1><div style="margin-bottom:12px">{model_link}</div><div class="card"><b>{e.patient}</b> · {e.exam_type}<br><span class="muted">{e.observation or 'Sem observação clínica.'}</span></div><div class="workspace"><section class="card viewer"><h2>Imagens / arquivos</h2>{imgs or 'Nenhum anexo.'}<hr style="margin:24px 0;border:0;border-top:1px solid #dce8ec"><h2>Exame pronto / Templates</h2><p class="muted">Anexe o exame final produzido pela radiologista em JPG/JPEG e/ou PDF. Os arquivos ficarão vinculados a este exame.</p><form method="post" action="/report/{e.id}/exame-pronto" enctype="multipart/form-data"><input type="file" name="finished_files" accept=".jpg,.jpeg,.pdf,image/jpeg,application/pdf" multiple required><button class="gold" type="submit">Anexar exame pronto</button></form>{ready_html or '<div class="notice">Nenhum template/exame pronto anexado ainda.</div>'}</section><section class="card editor"><h2>Laudo escrito</h2><form method="post"><textarea name="report" placeholder="Digite o laudo..." required>{e.report or ''}</textarea><label>Valor do laudo (R$)<input type="number" step="0.01" name="amount" value="0"></label><div class="editor-actions"><button type="button" onclick="localStorage.setItem('malibub_draft_{e.id}',document.querySelector('[name=report]').value);this.textContent='Rascunho salvo ✓'">Salvar rascunho</button><button class="gold" type="submit">Finalizar e liberar</button></div></form><script>const ta=document.querySelector('[name=report]');if(!ta.value)ta.value=localStorage.getItem('malibub_draft_{e.id}')||'';</script></section></div>'''
 return page(body)

@app.route("/result/<int:eid>/pdf")
def result_pdf(eid):
 if not session.get("uid"): return redirect("/")
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
 buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=16*mm,bottomMargin=18*mm,title=f"{e.protocol} - Laudo MALIBUB",author="MALIBUB Imaginologia Odontológica")
 styles=getSampleStyleSheet(); navy=colors.HexColor("#06394C"); teal=colors.HexColor("#087B9B"); gold=colors.HexColor("#C99B3B")
 title=ParagraphStyle("t",parent=styles["Heading1"],alignment=TA_CENTER,textColor=navy,fontSize=16,leading=20); body=ParagraphStyle("b",parent=styles["BodyText"],fontSize=10,leading=15,textColor=colors.HexColor("#26383D"))
 clinic=User.query.get(e.clinic_id)
 story=[]
 model_path=(UPLOAD/clinic.report_model) if clinic and clinic.report_model else None
 if model_path and model_path.exists() and model_path.suffix.lower() in {".jpg",".jpeg",".png"}:
  from reportlab.platypus import Image
  try:
   bg=Image(str(model_path)); bg._restrictSize(170*mm,48*mm); story += [bg,Spacer(1,4*mm)]
  except Exception: pass
 if not story: story=[Paragraph("MALIBUB",title),Paragraph("Imaginologia Odontológica",ParagraphStyle("s",parent=styles["Normal"],alignment=TA_CENTER,textColor=teal,fontSize=10)),Spacer(1,6*mm)]
 data=[["Protocolo",escape(e.protocol or "")],["Paciente",escape(e.patient or "")],["Exame",escape(e.exam_type or "")],["Dentista solicitante",escape(e.dentist or "")],["Data do exame",escape(e.exam_date or "")]]
 t=Table(data,colWidths=[42*mm,120*mm]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.4,colors.HexColor("#DCE8EC")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F1F6F7")),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("PADDING",(0,0),(-1,-1),6)])); story += [t,Spacer(1,7*mm),Paragraph("LAUDO RADIOLÓGICO",ParagraphStyle("h",parent=title,alignment=0,fontSize=12,textColor=navy)),Spacer(1,2*mm)]
 for line in (e.report or "").splitlines(): story.append(Paragraph(escape(line) or "&nbsp;",body))
 signer=escape(e.signed_by or "Dra. Marina"); signed=e.signed_at.strftime("%d/%m/%Y %H:%M") if e.signed_at else (e.released_at.strftime("%d/%m/%Y %H:%M") if e.released_at else "")
 story += [Spacer(1,12*mm),Table([[""]],colWidths=[70*mm],style=TableStyle([("LINEABOVE",(0,0),(-1,-1),.6,navy)])),Paragraph(f"<b>{signer}</b>",ParagraphStyle("sig",parent=body,alignment=TA_CENTER,textColor=navy)),Paragraph("Radiologista responsável",ParagraphStyle("sig2",parent=styles["Normal"],alignment=TA_CENTER,fontSize=8,textColor=colors.HexColor("#657F89"))),Spacer(1,3*mm),Paragraph(f"Assinado eletronicamente em {escape(signed)}",ParagraphStyle("f",parent=styles["Normal"],fontSize=8,textColor=colors.HexColor("#657F89"))),Paragraph(f"Validação MALIBUB · Protocolo {escape(e.protocol or '')}",ParagraphStyle("f3",parent=styles["Normal"],fontSize=7.5,textColor=colors.HexColor("#657F89"))),Spacer(1,2*mm),Paragraph((escape(clinic.name)+" · MALIBUB Imaginologia Odontológica") if clinic else "MALIBUB Imaginologia Odontológica",ParagraphStyle("f2",parent=styles["Normal"],fontSize=8,textColor=gold))]
 doc.build(story); buf.seek(0)
 # Quando a clínica cadastrou um PDF timbrado, use a primeira página como fundo
 # e sobreponha o laudo gerado, preservando a identidade visual da clínica.
 if model_path and model_path.exists() and model_path.suffix.lower()==".pdf":
  try:
   from pypdf import PdfReader, PdfWriter
   base_reader=PdfReader(str(model_path)); overlay_reader=PdfReader(buf)
   writer=PdfWriter()
   for idx,overlay_page in enumerate(overlay_reader.pages):
    if idx < len(base_reader.pages):
     base_page=base_reader.pages[idx]
    else:
     base_page=base_reader.pages[0]
    base_page.merge_page(overlay_page)
    writer.add_page(base_page)
   merged=io.BytesIO(); writer.write(merged); merged.seek(0); buf=merged
  except Exception:
   buf.seek(0)
 return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"{e.protocol}_laudo.pdf")

@app.route("/result/<int:eid>")
def result(eid):
 if not session.get("uid"): return redirect("/")
 e=Exam.query.get_or_404(eid)
 if session.get("role")=="Clinica" and e.clinic_id!=session.get("uid"): return redirect("/dashboard")
 if e.status!="Liberado": return redirect("/dashboard")
 ready=ExamFile.query.filter_by(exam_id=e.id,kind="exame_pronto").all()
 ready_html="".join((f"<div class='exam-file'><div class='filebar'><b>{f.name}</b><a class='btn' href='/exam-file/{f.id}' target='_blank'>Abrir</a><a class='btn gold' href='/exam-file/{f.id}?download=1'>Baixar</a></div>" + (f"<img src='/exam-file/{f.id}' alt='{f.name}'>" if f.name.lower().endswith(('.jpg','.jpeg')) else f"<iframe src='/exam-file/{f.id}' title='{f.name}'></iframe>") + "</div>") for f in ready)
 signed=(e.signed_at.strftime("%d/%m/%Y %H:%M") if e.signed_at else "")
 body=f'''<h1>Resultado — {e.protocol}</h1><div class="card"><div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap"><div><h2 style="margin:0 0 6px">{e.patient}</h2><div class="muted">{e.exam_type} · {e.dentist or 'Dentista não informado'}</div></div><span class="badge">{e.status}</span></div><hr><h3>Laudo radiológico</h3><div style="white-space:pre-wrap;min-height:220px;line-height:1.6">{e.report or 'Laudo não informado.'}</div><div style="margin-top:22px;padding-top:16px;border-top:1px solid #dce8ec"><b>{e.signed_by or 'Dra. Marina'}</b><br><span class="muted">Radiologista responsável · Assinado eletronicamente {signed}</span></div><hr><a class="btn gold" href="/result/{e.id}/pdf">Baixar laudo assinado em PDF</a><button onclick="window.print()">Imprimir</button></div><section class="card viewer"><h2>Exame pronto / Templates</h2><p class="muted">Arquivos finais disponibilizados pela radiologista.</p>{ready_html or '<div class="notice">Nenhum arquivo final foi anexado.</div>'}</section>'''
 return page(body)

@app.route("/finance",methods=["GET","POST"])
def finance():
 if session.get("role")!="Radiologista": return redirect("/")
 if request.method=="POST":
  db.session.add(Finance(description=request.form["description"],kind=request.form["kind"],amount=float(request.form["amount"] or 0))); db.session.commit()
 entries=Finance.query.order_by(Finance.date.desc()).all(); ent=sum(x.amount for x in entries if x.kind=="Entrada"); sai=sum(x.amount for x in entries if x.kind=="Saída")
 rows="".join(f"<tr><td>{x.date.strftime('%d/%m/%Y')}</td><td>{x.description}</td><td>{x.kind}</td><td>R$ {x.amount:.2f}</td></tr>" for x in entries)
 body=f'''<h1>Financeiro</h1><div class="cards"><div class="card">Entradas<b>R$ {ent:.2f}</b></div><div class="card">Saídas<b>R$ {sai:.2f}</b></div><div class="card">Saldo<b>R$ {ent-sai:.2f}</b></div></div><div class="card"><h2>Novo lançamento</h2><form method="post"><div class="grid"><label>Descrição<input name="description" required></label><label>Tipo<select name="kind"><option>Entrada</option><option>Saída</option></select></label><label>Valor<input type="number" step="0.01" name="amount" required></label></div><button>Adicionar</button></form></div><div class="card"><table><tr><th>Data</th><th>Descrição</th><th>Tipo</th><th>Valor</th></tr>{rows}</table></div>'''
 return page(body)

@app.route("/logout")
def logout(): session.clear(); return redirect("/")

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")))
