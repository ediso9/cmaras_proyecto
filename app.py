from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
import sqlite3, os, csv, io, json
import psycopg
from datetime import date, datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
load_dotenv()
DATABASE_URL=os.getenv('DATABASE_URL')
if not DATABASE_URL and os.getenv('SUPABASE_DB_HOST'):
 db_config={'host':os.getenv('SUPABASE_DB_HOST'),'port':os.getenv('SUPABASE_DB_PORT','5432'),'dbname':os.getenv('SUPABASE_DB_NAME','postgres'),'user':os.getenv('SUPABASE_DB_USER','postgres'),'password':os.getenv('SUPABASE_DB_PASSWORD'),'sslmode':'require'}
 missing=[key for key in ('host','password') if not db_config[key]]
 if missing: raise RuntimeError('Completa SUPABASE_DB_HOST y SUPABASE_DB_PASSWORD en .env.')
 DATABASE_URL=psycopg.conninfo.make_conninfo(**db_config)
SECRET_KEY=os.getenv('FLASK_SECRET_KEY'); DB=os.path.join(os.path.dirname(__file__),'riskvision.db')
if DATABASE_URL and not SECRET_KEY: raise RuntimeError('Configura FLASK_SECRET_KEY en .env antes de usar Supabase.')
app=Flask(__name__); app.secret_key=SECRET_KEY or 'riskvision-academic-demo-change-me'
IntegrityError=psycopg.IntegrityError if DATABASE_URL else sqlite3.IntegrityError
ASSETS=[
('ACT-001','Cámaras IP (1399)','Captura de video conectada a la red institucional','Videovigilancia','Central Alerta Miraflores','Responsable por validar','Alta'),
('ACT-002','Cámaras PTZ','Cámaras con movimiento horizontal, vertical y zoom controlado','Videovigilancia','Central Alerta Miraflores','Responsable por validar','Alta'),
('ACT-003','Plataforma IA','Analítica de video, reconocimiento facial, lectura de placas y detección de eventos','Aplicación','Por validar','Responsable por validar','Crítica'),
('ACT-004','Servidores de procesamiento','Equipos que ejecutan las analíticas de IA','Infraestructura','Por validar','Responsable por validar','Crítica'),
('ACT-005','Red institucional','Conecta cámaras, servidores y central de monitoreo','Red','Por validar','Responsable por validar','Crítica'),
('ACT-006','Base de datos','Repositorio de eventos, registros y trazabilidad','Datos','Por validar','Responsable por validar','Crítica'),
('ACT-007','Accesos remotos','Conexiones externas autorizadas para monitoreo y administración','Acceso','Por validar','Responsable por validar','Alta'),
('ACT-008','Central Alerta Miraflores','Aplicaciones y entorno de monitoreo operativo','Aplicación','Central Alerta Miraflores','Responsable por validar','Crítica')]
VULNS=[
('VUL-001','Credenciales por defecto','Credenciales débiles','Alta','Cámaras IP','NIST SP 800-53; documentación técnica de fabricantes'),
('VUL-002','Firmware desactualizado','Software desactualizado','Alta','Cámaras PTZ','Documentación técnica de fabricantes; NIST'),
('VUL-003','Configuraciones débiles','Configuración insegura','Alta','Plataforma IA','ISO/IEC 27002:2022; NIST SP 800-53'),
('VUL-004','Falta de cifrado','Falta de cifrado','Crítica','Servidores de procesamiento','ISO/IEC 27002:2022; NIST SP 800-53'),
('VUL-005','Segmentación insuficiente','Configuración insegura','Alta','Red institucional','ISO/IEC 27002:2022; NIST SP 800-53'),
('VUL-006','Controles de acceso débiles','Credenciales débiles','Alta','Base de datos','ISO/IEC 27002:2022; NIST SP 800-53'),
('VUL-007','Exposición a internet','Configuración insegura','Crítica','Accesos remotos','ENISA; documentación técnica de fabricantes')]
THREATS=[('Acceso no autorizado','Ingreso indebido a cámaras, cuentas o plataformas de IA.','ENISA Threat Landscape / escenario de referencia'),('Malware','Software malicioso que compromete servidores o equipos de red.','ENISA Threat Landscape / escenario de referencia'),('Fuerza bruta','Intentos repetidos de adivinar credenciales.','ENISA Threat Landscape / escenario de referencia'),('Denegación de servicio (DoS)','Saturación de recursos que afecta disponibilidad.','ENISA Threat Landscape / escenario de referencia'),('Interceptación de tráfico','Captura no autorizada de datos transmitidos por la red.','ENISA / escenario de referencia')]
SOB_DIMS=['Control tecnológico','Administración de datos','Dependencia de proveedores','Continuidad operativa']
POLICIES=[('ISO/IEC 27002:2022','Controles de seguridad de la información','Pendiente de revisión documental'),('Ley N.º 29733','Protección de datos personales','Pendiente de revisión documental'),('Decreto Legislativo N.º 1412','Gobierno digital','Pendiente de revisión documental'),('Ley N.º 30120','Apoyo a la seguridad ciudadana con videovigilancia','Pendiente de revisión documental')]
class DatabaseRow(dict):
 def __getitem__(self,key):
  if isinstance(key,int): return tuple(self.values())[key]
  return super().__getitem__(key)
def postgres_row_factory(cursor):
 def make_row(values): return DatabaseRow(zip((column.name for column in cursor.description),values))
 return make_row
class PostgresConnection:
 def __init__(self,connection): self.connection=connection
 def execute(self,sql,params=()): return self.connection.execute(sql.replace('?','%s'),params)
 def executemany(self,sql,rows): return self.connection.cursor().executemany(sql.replace('?','%s'),rows)
 def commit(self): self.connection.commit()
 def close(self): self.connection.close()
def db():
 if DATABASE_URL: return PostgresConnection(psycopg.connect(DATABASE_URL,row_factory=postgres_row_factory))
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def init(seed=True):
 c=db(); schema='''
 CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT);
 CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY,code TEXT UNIQUE,name TEXT,description TEXT,category TEXT,location TEXT,owner TEXT,criticality TEXT,evaluated INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS cameras(id INTEGER PRIMARY KEY,code TEXT UNIQUE,name TEXT,zone TEXT,kind TEXT,status TEXT,notes TEXT,asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL);
 CREATE TABLE IF NOT EXISTS camera_checks(id INTEGER PRIMARY KEY,camera_id INTEGER REFERENCES cameras(id) ON DELETE CASCADE,responded INTEGER NOT NULL,checked_at TEXT NOT NULL,mode TEXT DEFAULT 'simulado');
 CREATE TABLE IF NOT EXISTS vulnerabilities(id INTEGER PRIMARY KEY,code TEXT UNIQUE,title TEXT,kind TEXT,severity TEXT,asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,source TEXT NOT NULL,state TEXT,description TEXT);
 CREATE TABLE IF NOT EXISTS threats(id INTEGER PRIMARY KEY,name TEXT UNIQUE,description TEXT,source TEXT);
 CREATE TABLE IF NOT EXISTS risks(id INTEGER PRIMARY KEY,vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,threat_id INTEGER REFERENCES threats(id),p INTEGER,c INTEGER,i INTEGER,d INTEGER,impact INTEGER,score INTEGER,level TEXT,treatment_option TEXT,control TEXT,owner TEXT,start_date TEXT,due TEXT,status TEXT,notes TEXT);
 CREATE TABLE IF NOT EXISTS camera_alerts(id INTEGER PRIMARY KEY,camera_id INTEGER REFERENCES cameras(id) ON DELETE CASCADE,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Abierta',opened_at TEXT NOT NULL,closed_at TEXT,risk_id INTEGER REFERENCES risks(id) ON DELETE SET NULL);
 CREATE TABLE IF NOT EXISTS treatments(id INTEGER PRIMARY KEY,risk_id INTEGER REFERENCES risks(id) ON DELETE CASCADE,action TEXT,owner TEXT,start_date TEXT,due TEXT,status TEXT,control TEXT,notes TEXT);
 CREATE TABLE IF NOT EXISTS sovereignty(id INTEGER PRIMARY KEY,asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,provider TEXT,dimension TEXT,score INTEGER,justification TEXT,updated_at TEXT);
 CREATE TABLE IF NOT EXISTS policies(id INTEGER PRIMARY KEY,name TEXT,description TEXT,status TEXT,evidence TEXT);
 '''
 if DATABASE_URL: schema=schema.replace('id INTEGER PRIMARY KEY','id BIGSERIAL PRIMARY KEY')
 for statement in schema.split(';'):
  if statement.strip(): c.execute(statement)
 if seed:
  if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0: c.executemany('INSERT INTO users(username,password,role) VALUES(?,?,?)',[(u,generate_password_hash(pw),r) for u,pw,r in [('admin','admin123','Administrador'),('analista','analista123','Analista'),('auditor','auditor123','Auditor')]])
  # Migrar contraseñas antiguas de texto plano a hashes seguros.
  for user in c.execute('SELECT id,password FROM users').fetchall():
   if user['password'] and not user['password'].startswith(('scrypt:', 'pbkdf2:')):
    c.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(user['password']),user['id']))
  if c.execute('SELECT COUNT(*) FROM assets').fetchone()[0]==0: c.executemany('INSERT INTO assets(code,name,description,category,location,owner,criticality) VALUES(?,?,?,?,?,?,?)',ASSETS)
  if c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]==0:
   amap={r['name']:r['id'] for r in c.execute('SELECT id,name FROM assets')}
   c.executemany('INSERT INTO vulnerabilities(code,title,kind,severity,asset_id,source,state,description) VALUES(?,?,?,?,?,?,?,?)',[(code,title,kind,sev,amap.get(asset),src,'Potencial','Registro precargado a partir de la tabla de vulnerabilidades del documento; requiere validación documental, no implica comprobación en infraestructura municipal.') for code,title,kind,sev,asset,src in VULNS])
  if c.execute('SELECT COUNT(*) FROM threats').fetchone()[0]==0: c.executemany('INSERT INTO threats(name,description,source) VALUES(?,?,?)',THREATS)
  if c.execute('SELECT COUNT(*) FROM policies').fetchone()[0]==0: c.executemany('INSERT INTO policies(name,description,status) VALUES(?,?,?)',POLICIES)
 c.commit(); c.close()
def band(s): return 'Bajo' if s<=4 else 'Medio' if s<=9 else 'Alto' if s<=16 else 'Crítico'
def can_edit(): return session.get('role') in ('Administrador','Analista')
def guard():
 if not session.get('username'): return redirect(url_for('login'))
 return None
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  c=db(); u=c.execute('SELECT * FROM users WHERE username=?',(request.form['username'],)).fetchone(); c.close()
  if u and check_password_hash(u['password'],request.form['password']): session.update(username=u['username'],role=u['role']); return redirect(url_for('home'))
  flash('Usuario o contraseña incorrectos.')
 return render_template('login.html',page='login')
@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))
@app.before_request
def auth():
 if request.endpoint not in ('login','static') and not session.get('username'): return redirect(url_for('login'))
 if request.method=='POST' and request.endpoint not in ('login','logout') and not can_edit():
  flash('El rol Auditor tiene permisos de solo lectura.'); return redirect(request.referrer or url_for('home'))
def page(name, **kwargs): return render_template('module.html',page=name,role=session.get('role'),**kwargs)
def check_simulated_cameras(c):
 """Registra comprobaciones de disponibilidad únicamente sobre estados simulados."""
 now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
 cams=c.execute('SELECT * FROM cameras').fetchall()
 for cam in cams:
  # Solo el estado elegido en el laboratorio determina la respuesta; nunca se hace ping real.
  responded = 1 if cam['status'] in ('Disponible (simulado)','Simulada') else 0
  c.execute('INSERT INTO camera_checks(camera_id,responded,checked_at,mode) VALUES(?,?,?,?)',(cam['id'],responded,now,'simulado'))
  active=c.execute("SELECT id FROM camera_alerts WHERE camera_id=? AND status='Abierta' ORDER BY id DESC LIMIT 1",(cam['id'],)).fetchone()
  if not responded:
   if not active:
    c.execute('INSERT INTO camera_alerts(camera_id,message,status,opened_at) VALUES(?,?,?,?)',(cam['id'],'La cámara de laboratorio no responde en la comprobación simulada.','Abierta',now))
  elif active:
   c.execute("UPDATE camera_alerts SET status='Cerrada',closed_at=? WHERE id=?",(now,active['id']))
 c.commit()

@app.route('/')
def home():
 c=db(); assets=c.execute('SELECT COUNT(*) FROM assets').fetchone()[0]; vulns=c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]; threats=c.execute('SELECT COUNT(*) FROM threats').fetchone()[0]; risks=c.execute('SELECT * FROM risks').fetchall(); nrisks=len(risks); avg=round(sum(r['score'] for r in risks)/nrisks,2) if nrisks else 0; treated=c.execute("SELECT COUNT(DISTINCT risk_id) FROM treatments WHERE status='Completado'").fetchone()[0]; prt=round(treated/nrisks*100,1) if nrisks else 0; vtreated=c.execute("SELECT COUNT(DISTINCT v.id) FROM vulnerabilities v JOIN risks r ON r.vulnerability_id=v.id WHERE r.status='Completado'").fetchone()[0]; vtotal=c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]; vtp=round(vtreated/vtotal*100,1) if vtotal else 0
 # PAE is asset evaluated flag / total
 ev=c.execute('SELECT COUNT(*) FROM assets WHERE evaluated=1').fetchone()[0]; pae=round(ev/assets*100,1) if assets else 0
 sob=c.execute('SELECT score FROM sovereignty').fetchall(); sobidx=round(sum(x['score'] for x in sob)/(len(sob)*2)*100,1) if sob else 0
 overdue=c.execute("SELECT COUNT(*) FROM treatments WHERE due<>'' AND due < ? AND status!='Completado'",(date.today().isoformat(),)).fetchone()[0]; critical=c.execute("SELECT COUNT(*) FROM risks WHERE level='Crítico' AND status!='Completado'").fetchone()[0]; check_total=c.execute('SELECT COUNT(*) FROM camera_checks').fetchone()[0]; check_ok=c.execute('SELECT COUNT(*) FROM camera_checks WHERE responded=1').fetchone()[0]; availability=round(check_ok/check_total*100,1) if check_total else 0; open_alerts=c.execute("SELECT COUNT(*) FROM camera_alerts WHERE status='Abierta'").fetchone()[0]
 recent=c.execute('SELECT r.*,v.title vulnerability,t.name threat FROM risks r JOIN vulnerabilities v ON v.id=r.vulnerability_id LEFT JOIN threats t ON t.id=r.threat_id ORDER BY r.id DESC LIMIT 6').fetchall()
 heat=[]
 for p in range(5,0,-1):
  heat.append([{'p':p,'i':i,'score':p*i,'level':band(p*i),'count':c.execute('SELECT COUNT(*) FROM risks WHERE p=? AND impact=?',(p,i)).fetchone()[0]} for i in range(1,6)])
 c.close(); return page('home',stats={'assets':assets,'vulns':vulns,'threats':threats,'risks':nrisks,'avg':avg,'prt':prt,'vtp':vtp,'pae':pae,'sob':sobidx,'critical':critical,'overdue':overdue,'availability':availability,'open_alerts':open_alerts},recent=recent,heat=heat)
@app.route('/assets',methods=['GET','POST'])
def assets():
 c=db()
 if request.method=='POST':
  try:
   c.execute('INSERT INTO assets(code,name,description,category,location,owner,criticality,evaluated) VALUES(?,?,?,?,?,?,?,?)',(request.form['code'],request.form['name'],request.form.get('description',''),request.form.get('category','Otro'),request.form.get('location','Por validar'),request.form.get('owner','Por asignar'),request.form.get('criticality','Media'),int(request.form.get('evaluated','0')))); c.commit(); flash('Activo registrado.')
  except IntegrityError: flash('El código de activo ya existe.')
  c.close(); return redirect(url_for('assets'))
 rows=c.execute('SELECT a.*, (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id=a.id) vc FROM assets a ORDER BY a.id').fetchall(); c.close(); return page('assets',rows=rows)
@app.route('/assets/evaluated/<int:id>',methods=['POST'])
def asset_eval(id):
 c=db(); c.execute('UPDATE assets SET evaluated=? WHERE id=?',(int(request.form.get('evaluated','0')),id)); c.commit(); c.close(); return redirect(url_for('assets'))
@app.route('/cameras',methods=['GET','POST'])
def cameras():
 c=db()
 if request.method=='POST':
  try: c.execute('INSERT INTO cameras(code,name,zone,kind,status,notes,asset_id) VALUES(?,?,?,?,?,?,?)',(request.form['code'],request.form['name'],request.form.get('zone','Entorno simulado'),request.form.get('kind','IP simulada'),request.form.get('status','Simulada'),request.form.get('notes','Monitor de disponibilidad simulado; no hay conexión real.'),request.form.get('asset_id') or None)); c.commit(); flash('Cámara simulada registrada. No se conectó a un dispositivo real.')
  except IntegrityError: flash('El código de cámara ya existe.')
  c.close(); return redirect(url_for('cameras'))
 check_simulated_cameras(c); rows=c.execute('SELECT cam.*,a.name asset,(SELECT MAX(checked_at) FROM camera_checks cc WHERE cc.camera_id=cam.id) last_check FROM cameras cam LEFT JOIN assets a ON a.id=cam.asset_id ORDER BY cam.id DESC').fetchall(); aset=c.execute('SELECT * FROM assets').fetchall(); alerts=c.execute('SELECT al.*,cam.code camera_code,cam.name camera_name FROM camera_alerts al JOIN cameras cam ON cam.id=al.camera_id ORDER BY al.id DESC LIMIT 50').fetchall(); counts=c.execute('SELECT COUNT(*) total,COALESCE(SUM(responded),0) ok FROM camera_checks').fetchone(); availability=round(counts['ok']/counts['total']*100,1) if counts['total'] else 0; c.close(); return page('cameras',rows=rows,assets=aset,alerts=alerts,availability=availability)
@app.route('/cameras/status/<int:id>',methods=['POST'])
def camstatus(id):
 c=db(); c.execute('UPDATE cameras SET status=? WHERE id=?',(request.form['status'],id)); check_simulated_cameras(c); c.close(); flash('Estado simulado actualizado y disponibilidad comprobada.'); return redirect(url_for('cameras'))

@app.route('/cameras/check',methods=['POST'])
def camera_check_now():
 c=db(); check_simulated_cameras(c); c.close(); flash('Comprobación simulada ejecutada; las alertas se abrieron o cerraron según el estado seleccionado.'); return redirect(url_for('cameras'))

@app.route('/cameras/auto-check')
def camera_auto_check():
 c=db(); check_simulated_cameras(c); c.close(); return {'ok':True,'mode':'simulado','message':'Comprobación de estados simulados completada.'}
@app.route('/cameras/alerts/<int:alert_id>/risk',methods=['POST'])
def camera_alert_to_risk(alert_id):
 c=db(); alert=c.execute("SELECT al.*,cam.name camera_name,cam.asset_id FROM camera_alerts al JOIN cameras cam ON cam.id=al.camera_id WHERE al.id=?",(alert_id,)).fetchone()
 if not alert:
  c.close(); flash('No se encontró la alerta.'); return redirect(url_for('cameras'))
 if alert['risk_id']:
  c.close(); flash('Esta alerta ya está vinculada al riesgo registrado.'); return redirect(url_for('cameras'))
 vuln=c.execute("SELECT id FROM vulnerabilities WHERE code='VUL-CAM-DISP' LIMIT 1").fetchone()
 if not vuln:
  c.execute("INSERT INTO vulnerabilities(code,title,kind,severity,asset_id,source,state,description) VALUES(?,?,?,?,?,?,?,?)",('VUL-CAM-DISP','Indisponibilidad de cámara en entorno simulado','Configuración insegura','Media',alert['asset_id'],'Registro de simulación RiskVision','Potencial','Vulnerabilidad/escenario creado a partir de una alerta simulada; no demuestra una falla real.'))
  vid=c.execute("SELECT id FROM vulnerabilities WHERE code='VUL-CAM-DISP'").fetchone()['id']
 else: vid=vuln['id']
 threat=c.execute("SELECT id FROM threats WHERE name='Denegación de servicio (DoS)'").fetchone()
 if not threat:
  c.execute('INSERT INTO threats(name,description,source) VALUES(?,?,?)',('Denegación de servicio (DoS)','Pérdida de disponibilidad del servicio.','Escenario académico simulado'))
  threat=c.execute("SELECT id FROM threats WHERE name='Denegación de servicio (DoS)'").fetchone()
 p,cval,ival,dval=3,1,2,4; impact=max(cval,ival,dval); score=p*impact
 rid=c.execute('INSERT INTO risks(vulnerability_id,threat_id,p,c,i,d,impact,score,level,treatment_option,control,owner,start_date,due,status,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id',(vid,threat['id'],p,cval,ival,dval,impact,score,band(score),'Mitigar','ISO/IEC 27002:2022 — por mapear','Por asignar',date.today().isoformat(),'','Pendiente','Generado desde alerta de disponibilidad simulada. No representa una cámara real.')).fetchone()[0]; c.execute('UPDATE camera_alerts SET risk_id=? WHERE id=?',(rid,alert_id)); c.commit(); c.close(); flash(f'Alerta convertida en riesgo de referencia ({score}/25, {band(score)}).'); return redirect(url_for('cameras'))

@app.route('/vulnerabilities',methods=['GET','POST'])
def vulnerabilities():
 c=db()
 if request.method=='POST':
  try: c.execute('INSERT INTO vulnerabilities(code,title,kind,severity,asset_id,source,state,description) VALUES(?,?,?,?,?,?,?,?)',(request.form['code'],request.form['title'],request.form['kind'],request.form['severity'],request.form.get('asset_id') or None,request.form['source'],request.form.get('state','Potencial'),request.form.get('description',''))); c.commit(); flash('Vulnerabilidad registrada.')
  except IntegrityError: flash('El código ya existe; usa otro código.')
  c.close(); return redirect(url_for('vulnerabilities'))
 rows=c.execute('SELECT v.*,a.name asset FROM vulnerabilities v LEFT JOIN assets a ON a.id=v.asset_id ORDER BY v.id').fetchall(); aset=c.execute('SELECT * FROM assets').fetchall(); c.close(); return page('vulnerabilities',rows=rows,assets=aset)
@app.route('/threats',methods=['GET','POST'])
def threats():
 c=db()
 if request.method=='POST':
  try: c.execute('INSERT INTO threats(name,description,source) VALUES(?,?,?)',(request.form['name'],request.form['description'],request.form.get('source','Fuente por validar'))); c.commit(); flash('Amenaza registrada.')
  except IntegrityError: flash('Esa amenaza ya existe.')
  c.close(); return redirect(url_for('threats'))
 rows=c.execute('SELECT * FROM threats ORDER BY id').fetchall(); c.close(); return page('threats',rows=rows)
@app.route('/risks',methods=['GET','POST'])
def risks():
 c=db()
 if request.method=='POST':
  vid=int(request.form['vulnerability_id']); tid=int(request.form['threat_id']); p=int(request.form['p']); vals=[int(request.form[x]) for x in ('c','i','d')]; impact=max(vals); score=p*impact; opt=request.form.get('treatment_option','Mitigar'); vuln=c.execute('SELECT kind FROM vulnerabilities WHERE id=?',(vid,)).fetchone(); suggestions={'Credenciales débiles':'Mitigar: MFA, política de contraseñas y control de intentos.','Software desactualizado':'Mitigar: inventario de versiones y parcheo controlado.','Configuración insegura':'Mitigar: endurecimiento de configuración y revisión de reglas.','Falta de cifrado':'Mitigar: cifrado en tránsito y en reposo, con gestión de claves.'}; sug=suggestions.get(vuln['kind'],'Mitigar: aplicar controles preventivos y verificar evidencias.')
  c.execute('INSERT INTO risks(vulnerability_id,threat_id,p,c,i,d,impact,score,level,treatment_option,control,owner,start_date,due,status,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(vid,tid,p,*vals,impact,score,band(score),opt,request.form.get('control','ISO/IEC 27002:2022'),request.form.get('owner','Por asignar'),request.form.get('start_date',''),request.form.get('due',''),request.form.get('status','Pendiente'),sug+' '+request.form.get('notes',''))); c.commit(); flash(f'Riesgo creado: {score}/25 ({band(score)}). Recomendación: {sug}')
  c.close(); return redirect(url_for('risks'))
 rows=c.execute('SELECT r.*,v.title vulnerability,v.code vcode,t.name threat FROM risks r JOIN vulnerabilities v ON v.id=r.vulnerability_id JOIN threats t ON t.id=r.threat_id ORDER BY r.score DESC').fetchall(); vs=c.execute('SELECT * FROM vulnerabilities').fetchall(); ts=c.execute('SELECT * FROM threats').fetchall(); c.close(); return page('risks',rows=rows,vulnerabilities=vs,threats=ts)
@app.route('/treatments',methods=['GET','POST'])
def treatments():
 c=db()
 if request.method=='POST':
  c.execute('INSERT INTO treatments(risk_id,action,owner,start_date,due,status,control,notes) VALUES(?,?,?,?,?,?,?,?)',(int(request.form['risk_id']),request.form['action'],request.form.get('owner','Por asignar'),request.form.get('start_date',''),request.form.get('due',''),request.form.get('status','Pendiente'),request.form.get('control','ISO/IEC 27002:2022'),request.form.get('notes',''))); c.commit(); flash('Tratamiento registrado en su módulo independiente.')
  c.close(); return redirect(url_for('treatments'))
 rows=c.execute('SELECT tr.*,r.score,r.level,v.title vulnerability,t.name threat FROM treatments tr JOIN risks r ON r.id=tr.risk_id JOIN vulnerabilities v ON v.id=r.vulnerability_id JOIN threats t ON t.id=r.threat_id ORDER BY tr.id DESC').fetchall(); riskslist=c.execute('SELECT r.id,r.score,r.level,v.title vulnerability,t.name threat FROM risks r JOIN vulnerabilities v ON v.id=r.vulnerability_id JOIN threats t ON t.id=r.threat_id').fetchall(); c.close(); return page('treatments',rows=rows,risks=riskslist)
@app.route('/treatments/status/<int:id>',methods=['POST'])
def treatment_status(id):
 c=db(); status=request.form['status']; c.execute('UPDATE treatments SET status=? WHERE id=?',(status,id)); c.execute('UPDATE risks SET status=? WHERE id=(SELECT risk_id FROM treatments WHERE id=?)',(status,id)); c.commit(); c.close(); return redirect(url_for('treatments'))
@app.route('/indicators',methods=['GET'])
def indicators():
 c=db(); total=c.execute('SELECT COUNT(*) FROM assets').fetchone()[0]; ev=c.execute('SELECT COUNT(*) FROM assets WHERE evaluated=1').fetchone()[0]; nr=c.execute('SELECT COUNT(*) FROM risks').fetchone()[0]; treated=c.execute("SELECT COUNT(DISTINCT risk_id) FROM treatments WHERE status='Completado'").fetchone()[0]; nv=c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]; vt=c.execute("SELECT COUNT(DISTINCT v.id) FROM vulnerabilities v JOIN risks r ON r.vulnerability_id=v.id WHERE r.status='Completado'").fetchone()[0]; avg=c.execute('SELECT AVG(score) FROM risks').fetchone()[0] or 0; pol=c.execute('SELECT COUNT(*) FROM policies').fetchone()[0]; polok=c.execute("SELECT COUNT(*) FROM policies WHERE status='Cumple'").fetchone()[0]; checks=c.execute('SELECT COUNT(*) total,COALESCE(SUM(responded),0) ok FROM camera_checks').fetchone(); availability=round(checks['ok']/checks['total']*100,1) if checks['total'] else 0; c.close(); data=[('PAE','Porcentaje de activos evaluados',round(ev/total*100,1) if total else 0,'(Activos marcados como evaluados / Total de activos) × 100'),('PRT','Porcentaje de riesgos con tratamiento completado',round(treated/nr*100,1) if nr else 0,'(Riesgos con al menos un tratamiento en estado Completado / Total de riesgos evaluados) × 100'),('% vulnerabilidades tratadas','Vulnerabilidades con riesgo asociado completado',round(vt/nv*100,1) if nv else 0,'(Vulnerabilidades con al menos un riesgo en estado Completado / Total de vulnerabilidades registradas) × 100'),('Riesgo promedio','Promedio del puntaje de riesgos',round(avg,2),'Suma de puntajes de riesgo / Número de riesgos evaluados'),('Disponibilidad','Porcentaje de comprobaciones simuladas con respuesta',availability,'(Comprobaciones simuladas con respuesta / Total de comprobaciones simuladas) × 100'),('% cumplimiento de políticas','Políticas con estado Cumple',round(polok/pol*100,1) if pol else 0,'(Políticas marcadas Cumple / Total de políticas registradas) × 100')]; return page('indicators',indicators=data)
@app.route('/sovereignty',methods=['GET','POST'])
def sovereignty():
 c=db()
 if request.method=='POST':
  aid=int(request.form['asset_id']); provider=request.form.get('provider','No documentado'); dimension=request.form['dimension']; score=int(request.form['score']); justification=request.form.get('justification',''); c.execute('INSERT INTO sovereignty(asset_id,provider,dimension,score,justification,updated_at) VALUES(?,?,?,?,?,?)',(aid,provider,dimension,score,justification,datetime.now().strftime('%Y-%m-%d %H:%M'))); c.commit(); flash('Evaluación de soberanía guardada.')
  if request.form.get('generate_risk')=='yes' and dimension=='Dependencia de proveedores' and score==0:
   v=c.execute("SELECT id FROM vulnerabilities WHERE title LIKE '%proveedor%' OR title LIKE '%Exposición a internet%' LIMIT 1").fetchone(); t=c.execute("SELECT id FROM threats WHERE name='Acceso no autorizado'").fetchone()
   if v and t: p=4; impact=4; s=p*impact; c.execute('INSERT INTO risks(vulnerability_id,threat_id,p,c,i,d,impact,score,level,treatment_option,control,owner,start_date,due,status,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(v['id'],t['id'],p,4,4,3,impact,s,band(s),'Mitigar','ISO/IEC 27002:2022','Por asignar','','','Pendiente','Generado automáticamente desde cuestionario de soberanía; escenario de referencia por dependencia de proveedor.')); c.commit(); flash('Se generó un riesgo de dependencia como escenario de referencia.')
  c.close(); return redirect(url_for('sovereignty'))
 rows=c.execute('SELECT s.*,a.name asset FROM sovereignty s JOIN assets a ON a.id=s.asset_id ORDER BY s.id DESC').fetchall(); aset=c.execute('SELECT * FROM assets').fetchall(); scores=c.execute('SELECT score FROM sovereignty').fetchall(); idx=round(sum(r['score'] for r in scores)/(len(scores)*2)*100,1) if scores else 0; c.close(); return page('sovereignty',rows=rows,assets=aset,dimensions=SOB_DIMS,index=idx)
@app.route('/policies',methods=['GET','POST'])
def policies():
 c=db()
 if request.method=='POST': c.execute('UPDATE policies SET status=?,evidence=? WHERE id=?',(request.form['status'],request.form.get('evidence',''),int(request.form['id']))); c.commit(); c.close(); flash('Estado de revisión normativa actualizado.'); return redirect(url_for('policies'))
 rows=c.execute('SELECT * FROM policies').fetchall(); c.close(); return page('policies',rows=rows)
@app.route('/reports')
def reports():
 c=db(); summary={t:c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ['assets','vulnerabilities','threats','risks','treatments','sovereignty','camera_alerts']}; rows=c.execute('SELECT r.*,v.code vcode,v.title vulnerability,t.name threat FROM risks r JOIN vulnerabilities v ON v.id=r.vulnerability_id JOIN threats t ON t.id=r.threat_id ORDER BY r.score DESC').fetchall(); assetsrows=c.execute('SELECT * FROM assets ORDER BY id').fetchall(); vulnrows=c.execute('SELECT v.*,a.name asset FROM vulnerabilities v LEFT JOIN assets a ON a.id=v.asset_id ORDER BY v.id').fetchall(); threatrows=c.execute('SELECT * FROM threats ORDER BY id').fetchall(); treatmentrows=c.execute('SELECT tr.*,r.score,r.level,v.title vulnerability FROM treatments tr JOIN risks r ON r.id=tr.risk_id JOIN vulnerabilities v ON v.id=r.vulnerability_id ORDER BY tr.id').fetchall(); sobrows=c.execute('SELECT s.*,a.name asset FROM sovereignty s JOIN assets a ON a.id=s.asset_id ORDER BY s.id').fetchall(); policyrows=c.execute('SELECT * FROM policies').fetchall(); c.close(); return page('reports',summary=summary,rows=rows,assetsrows=assetsrows,vulnrows=vulnrows,threatrows=threatrows,treatmentrows=treatmentrows,sobrows=sobrows,policyrows=policyrows)
@app.route('/export/<kind>')
def export(kind):
 allowed={'cameras':'SELECT code,name,zone,kind,status,notes,asset_id FROM cameras','assets':'SELECT code,name,description,category,location,owner,criticality,evaluated FROM assets','vulnerabilities':'SELECT code,title,kind,severity,asset_id,source,state,description FROM vulnerabilities','threats':'SELECT name,description,source FROM threats','risks':'SELECT id,vulnerability_id,threat_id,p,c,i,d,impact,score,level,treatment_option,control,owner,start_date,due,status,notes FROM risks','treatments':'SELECT * FROM treatments','sovereignty':'SELECT * FROM sovereignty','policies':'SELECT * FROM policies','camera_alerts':'SELECT id,camera_id,message,status,opened_at,closed_at,risk_id FROM camera_alerts'}
 if kind not in allowed: return 'Tipo no válido',404
 c=db(); rows=c.execute(allowed[kind]).fetchall(); c.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['sin_registros']); [w.writerow(tuple(r)) for r in rows]; return Response('\ufeff'+out.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename=riskvision_{kind}.csv'})
if __name__=='__main__': init(seed=not DATABASE_URL); app.run(debug=False)
