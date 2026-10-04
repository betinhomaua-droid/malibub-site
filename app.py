from flask import Flask, request, redirect, url_for, session, flash, render_template_string, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from pathlib import Path
import os, uuid

app=Flask(__name__)
app.config["SECRET_KEY"]=os.getenv("SECRET_KEY","malibub-homologacao")
app.config["SQLALCHEMY_DATABASE_URI"]=os.getenv("DATABASE_URL","sqlite:///malibub.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config["MAX_CONTENT_LENGTH"]=200*1024*1024
db=SQLAlchemy(app)
UPLOAD=Path(app.instance_path)/"uploads"; UPLOAD.mkdir(parents=True,exist_ok=True)

@app.route("/assets/<path:filename>")
def assets(filename):
 return send_from_directory(Path(app.root_path)/"assets", filename)

class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(100)); email=db.Column(db.String(120),unique=True); password=db.Column(db.String(255)); role=db.Column(db.String(30))
class Exam(db.Model):
 id=db.Column(db.Integer,primary_key=True); protocol=db.Column(db.String(30),unique=True); patient=db.Column(db.String(120)); sex=db.Column(db.String(20)); birth=db.Column(db.String(20)); dentist=db.Column(db.String(120)); exam_date=db.Column(db.String(20)); exam_type=db.Column(db.String(100)); observation=db.Column(db.String(500)); status=db.Column(db.String(50),default="Enviado"); clinic_id=db.Column(db.Integer); due_at=db.Column(db.DateTime); report=db.Column(db.Text,default=""); released_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=datetime.utcnow)
class ExamFile(db.Model):
 id=db.Column(db.Integer,primary_key=True); exam_id=db.Column(db.Integer); name=db.Column(db.String(255)); stored=db.Column(db.String(255))
class Finance(db.Model):
 id=db.Column(db.Integer,primary_key=True); date=db.Column(db.Date,default=datetime.utcnow().date); description=db.Column(db.String(200)); kind=db.Column(db.String(20)); amount=db.Column(db.Float,default=0)

CSS="""*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#f4f8fa;color:#153847}a{text-decoration:none;color:#087b9b}.shell{display:grid;grid-template-columns:220px 1fr;min-height:100vh}aside{background:linear-gradient(180deg,#06394c,#087b9b);color:white;padding:28px 20px}aside a{color:white;display:block;margin:20px 0}.brand{font-size:25px;font-weight:800}.brand span{display:block;font-weight:400}.brand small{display:block;font-size:10px;margin-top:8px}main{padding:32px;max-width:1500px}.card{background:white;border:1px solid #dce8ec;border-radius:16px;padding:22px;margin-bottom:18px;box-shadow:0 5px 18px #0c40540d}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}input,select,textarea{width:100%;padding:11px;border:1px solid #cbdde3;border-radius:8px;margin-top:6px}label{font-weight:700}button,.btn{display:inline-block;background:#087b9b;color:white;border:0;border-radius:8px;padding:11px 16px;margin:8px 5px 5px 0}.gold{background:#c99b3b}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #e5edef}.badge{background:#e6f4f7;padding:5px 9px;border-radius:12px}.workspace{display:grid;grid-template-columns:1fr 1fr;gap:18px}.viewer{max-height:650px;overflow:auto}.viewer img{width:100%;margin-bottom:10px;border-radius:8px}.editor textarea{min-height:430px}.muted{color:#657f89}.notice{padding:12px;background:#fff7df;border-left:4px solid #c99b3b;margin:12px 0}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.cards .card b{display:block;font-size:28px;color:#087b9b}
.login-approved{min-height:100vh;display:grid;grid-template-columns:52.5% 47.5%;background:#020b14;color:white;overflow:hidden}
.login-visual{background:#06192a url('/assets/borboleta.png') center/cover no-repeat;display:flex;align-items:flex-end;justify-content:center;padding:0 7% 12%;text-align:center;position:relative}
.login-visual:after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent 55%,#020b1490 100%);pointer-events:none}
.login-copy{position:relative;z-index:1}.login-copy h1{font-size:42px;line-height:1.18;margin:0 0 18px;color:#fff}.login-copy h1 span{color:#20d8ef}.login-copy p{font-size:20px;margin:0;color:#d8e2e8}
.login-panel{display:flex;align-items:center;justify-content:center;background:radial-gradient(circle at 50% 45%,#0a2436 0,#020b14 58%);padding:42px}
.login-card{width:min(540px,100%)}.login-card h2{font-size:30px;margin:0 0 8px}.login-card .sub{color:#9cb0bd;margin:0 0 28px}
.login-card label{display:block;color:#fff;font-size:16px;margin:16px 0 7px}.login-card input{height:56px;margin:0;background:#07131f;border:1px solid #526574;border-radius:10px;color:#fff;font-size:16px;padding:0 48px 0 16px;outline:none}.login-card input:focus{border-color:#20d8ef;box-shadow:0 0 0 2px #20d8ef2e}
.login-card .pass-wrap{position:relative}.login-card .pass-wrap input{width:100%}.login-card .eye{position:absolute;right:8px;bottom:7px;width:42px;height:42px;padding:0;margin:0;background:transparent;color:#c8d3da;border:0;font-size:20px}
.login-card .submit{width:100%;height:56px;margin:20px 0 0;border:0;border-radius:10px;background:linear-gradient(90deg,#14cfe7,#1de4ed);color:#00121c;font-size:18px;font-weight:800}
.login-card .foot{text-align:center;color:#9cb0bd;margin-top:22px;font-size:14px}.login-card .foot b{color:#20d8ef}.login-flash{padding:11px 13px;border:1px solid #d9a441;background:#251d0d;color:#fff;border-radius:8px;margin-bottom:15px}
.login-footer{position:fixed;bottom:8px;left:0;right:0;text-align:center;color:#c7d2d9;font-size:12px;pointer-events:none}
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
 <section class="login-visual"><div class="login-copy"><h1>Laudos com precisão.<br><span>Imagens que voam.</span></h1><p>Envio e Retirada de exames em um só lugar.</p></div></section>
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
 body=f'''<h1>Painel {'da Clínica' if session["role"]=="Clinica" else 'da Radiologista'}</h1><p>Olá, {session["name"]}.</p>{'<a class="btn gold" href="/new">+ Novo Exame</a>' if session["role"]=="Clinica" else ''}<div class="card"><h2>Exames</h2><table><tr><th>Protocolo</th><th>Paciente</th><th>Exame</th><th>Status</th><th>Ação</th></tr>{rows or '<tr><td colspan=5>Nenhum exame.</td></tr>'}</table></div>'''
 return page(body)

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

@app.route("/report/<int:eid>",methods=["GET","POST"])
def report(eid):
 if session.get("role")!="Radiologista": return redirect("/")
 e=Exam.query.get_or_404(eid); files=ExamFile.query.filter_by(exam_id=e.id).all()
 if request.method=="POST":
  e.report=request.form["report"]; e.status="Liberado"; e.released_at=datetime.utcnow(); db.session.add(Finance(description=f"Laudo {e.protocol}",kind="Entrada",amount=float(request.form.get("amount") or 0))); db.session.commit(); return redirect("/dashboard")
 imgs="".join(f"<div class='card'><b>{f.name}</b></div>" for f in files)
 body=f'''<h1>Ambiente da Radiologista — {e.protocol}</h1><div class="card"><b>{e.patient}</b> · {e.exam_type}<br><span class="muted">{e.observation or 'Sem observação clínica.'}</span></div><div class="workspace"><section class="card viewer"><h2>Imagens / arquivos</h2>{imgs or 'Nenhum anexo.'}</section><section class="card editor"><h2>Laudo escrito</h2><form method="post"><textarea name="report" placeholder="Digite o laudo..." required>{e.report or ''}</textarea><label>Valor do laudo (R$)<input type="number" step="0.01" name="amount" value="0"></label><button>Salvar rascunho</button><button class="gold" type="submit">Finalizar e liberar</button></form></section></div>'''
 return page(body)

@app.route("/result/<int:eid>")
def result(eid):
 if not session.get("uid"): return redirect("/")
 e=Exam.query.get_or_404(eid)
 body=f'''<h1>Resultado — {e.protocol}</h1><div class="card"><h2>{e.patient}</h2><p>{e.exam_type}</p><hr><div style="white-space:pre-wrap;min-height:280px">{e.report}</div><button onclick="window.print()">Imprimir / Salvar PDF</button></div>'''
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
