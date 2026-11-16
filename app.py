from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
import sqlite3, os, csv, io, json
import psycopg
from datetime import date, datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL and os.getenv('SUPABASE_DB_HOST'):
    db_config = {
        'host': os.getenv('SUPABASE_DB_HOST'),
        'port': os.getenv('SUPABASE_DB_PORT', '5432'),
        'dbname': os.getenv('SUPABASE_DB_NAME', 'postgres'),
        'user': os.getenv('SUPABASE_DB_USER', 'postgres'),
        'password': os.getenv('SUPABASE_DB_PASSWORD'),
        'sslmode': 'require'
    }
    missing = [key for key in ('host', 'password') if not db_config[key]]
    if missing:
        raise RuntimeError('Completa SUPABASE_DB_HOST y SUPABASE_DB_PASSWORD en .env.')
    DATABASE_URL = psycopg.conninfo.make_conninfo(**db_config)

SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
DB = os.path.join(os.path.dirname(__file__), 'riskvision.db')
if DATABASE_URL and not SECRET_KEY:
    raise RuntimeError('Configura FLASK_SECRET_KEY en .env antes de usar Supabase.')

app = Flask(__name__)
app.secret_key = SECRET_KEY or 'riskvision-academic-demo-change-me'
IntegrityError = psycopg.IntegrityError if DATABASE_URL else sqlite3.IntegrityError

ASSETS = [
    ('ACT-001', 'Cámaras IP (1399)', 'Captura de video conectada a la red institucional', 'Videovigilancia', 'Central Alerta Miraflores', 'Responsable por validar', 'Alta'),
    ('ACT-002', 'Cámaras PTZ', 'Cámaras con movimiento horizontal, vertical y zoom controlado', 'Videovigilancia', 'Central Alerta Miraflores', 'Responsable por validar', 'Alta'),
    ('ACT-003', 'Plataforma IA', 'Analítica de video, reconocimiento facial, lectura de placas y detección de eventos', 'Aplicación', 'Por validar', 'Responsable por validar', 'Crítica'),
    ('ACT-004', 'Servidores de procesamiento', 'Equipos que ejecutan las analíticas de IA', 'Infraestructura', 'Por validar', 'Responsable por validar', 'Crítica'),
    ('ACT-005', 'Red institucional', 'Conecta cámaras, servidores y central de monitoreo', 'Red', 'Por validar', 'Responsable por validar', 'Crítica'),
    ('ACT-006', 'Base de datos', 'Repositorio de eventos, registros y trazabilidad', 'Datos', 'Por validar', 'Responsable por validar', 'Crítica'),
    ('ACT-007', 'Accesos remotos', 'Conexiones externas autorizadas para monitoreo y administración', 'Acceso', 'Por validar', 'Responsable por validar', 'Alta'),
    ('ACT-008', 'Central Alerta Miraflores', 'Aplicaciones y entorno de monitoreo operativo', 'Aplicación', 'Central Alerta Miraflores', 'Responsable por validar', 'Crítica')
]

VULNS = [
    ('VUL-001', 'Credenciales por defecto', 'Credenciales débiles', 'Alta', 'Cámaras IP', 'NIST SP 800-53; documentación técnica de fabricantes'),
    ('VUL-002', 'Firmware desactualizado', 'Software desactualizado', 'Alta', 'Cámaras PTZ', 'Documentación técnica de fabricantes; NIST'),
    ('VUL-003', 'Configuraciones débiles', 'Configuración insegura', 'Alta', 'Plataforma IA', 'ISO/IEC 27002:2022; NIST SP 800-53'),
    ('VUL-004', 'Falta de cifrado', 'Falta de cifrado', 'Crítica', 'Servidores de procesamiento', 'ISO/IEC 27002:2022; NIST SP 800-53'),
    ('VUL-005', 'Segmentación insuficiente', 'Configuración insegura', 'Alta', 'Red institucional', 'ISO/IEC 27002:2022; NIST SP 800-53'),
    ('VUL-006', 'Controles de acceso débiles', 'Credenciales débiles', 'Alta', 'Base de datos', 'ISO/IEC 27002:2022; NIST SP 800-53'),
    ('VUL-007', 'Exposición a internet', 'Configuración insegura', 'Crítica', 'Accesos remotos', 'ENISA; documentación técnica de fabricantes')
]

THREATS = [
    ('Acceso no autorizado', 'Ingreso indebido a cámaras, cuentas o plataformas de IA.', 'ENISA Threat Landscape / escenario de referencia'),
    ('Malware', 'Software malicioso que compromete servidores o equipos de red.', 'ENISA Threat Landscape / escenario de referencia'),
    ('Fuerza bruta', 'Intentos repetidos de adivinar credenciales.', 'ENISA Threat Landscape / escenario de referencia'),
    ('Denegación de servicio (DoS)', 'Saturación de recursos que afecta disponibilidad.', 'ENISA Threat Landscape / escenario de referencia'),
    ('Interceptación de tráfico', 'Captura no autorizada de datos transmitidos por la red.', 'ENISA / escenario de referencia')
]

SOB_DIMS = ['Control tecnológico', 'Administración de datos', 'Dependencia de proveedores', 'Continuidad operativa']

POLICIES = [
    ('ISO/IEC 27002:2022', 'Controles de seguridad de la información', 'Pendiente de revisión documental'),
    ('Ley N.º 29733', 'Protección de datos personales', 'Pendiente de revisión documental'),
    ('Decreto Legislativo N.º 1412', 'Gobierno digital', 'Pendiente de revisión documental'),
    ('Ley N.º 30120', 'Apoyo a la seguridad ciudadana con videovigilancia', 'Pendiente de revisión documental')
]

class DatabaseRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)

def postgres_row_factory(cursor):
    def make_row(values):
        return DatabaseRow(zip((column.name for column in cursor.description), values))
    return make_row

class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection
    def execute(self, sql, params=()):
        return self.connection.execute(sql.replace('?', '%s'), params)
    def executemany(self, sql, rows):
        return self.connection.cursor().executemany(sql.replace('?', '%s'), rows)
    def commit(self):
        self.connection.commit()
    def close(self):
        self.connection.close()

def db():
    if DATABASE_URL:
        return PostgresConnection(psycopg.connect(DATABASE_URL, row_factory=postgres_row_factory))
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def init(seed=True):
    c = db()
    schema = '''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT);
    CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY,code TEXT UNIQUE,name TEXT,description TEXT,category TEXT,location TEXT,owner TEXT,criticality TEXT,evaluated INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS vulnerabilities(id INTEGER PRIMARY KEY,code TEXT UNIQUE,title TEXT,kind TEXT,severity TEXT,asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,source TEXT NOT NULL,state TEXT,description TEXT);
    CREATE TABLE IF NOT EXISTS threats(id INTEGER PRIMARY KEY,name TEXT UNIQUE,description TEXT,source TEXT);
    CREATE TABLE IF NOT EXISTS risks(id INTEGER PRIMARY KEY,vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,threat_id INTEGER REFERENCES threats(id),p INTEGER,c INTEGER,i INTEGER,d INTEGER,impact INTEGER,score INTEGER,level TEXT,treatment_option TEXT,control TEXT,owner TEXT,start_date TEXT,due TEXT,status TEXT,notes TEXT);
    CREATE TABLE IF NOT EXISTS treatments(id INTEGER PRIMARY KEY,risk_id INTEGER REFERENCES risks(id) ON DELETE CASCADE,action TEXT,owner TEXT,start_date TEXT,due TEXT,status TEXT,control TEXT,notes TEXT);
    CREATE TABLE IF NOT EXISTS sovereignty(id INTEGER PRIMARY KEY,asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,provider TEXT,dimension TEXT,score INTEGER,justification TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS policies(id INTEGER PRIMARY KEY,name TEXT,description TEXT,status TEXT,evidence TEXT);
    '''
    if DATABASE_URL:
        schema = schema.replace('id INTEGER PRIMARY KEY', 'id BIGSERIAL PRIMARY KEY')
    for statement in schema.split(';'):
        if statement.strip():
            c.execute(statement)
    if seed:
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            c.executemany('INSERT INTO users(username,password,role) VALUES(?,?,?)', [(u, generate_password_hash(pw), r) for u, pw, r in [('admin', 'admin123', 'Administrador'), ('analista', 'analista123', 'Analista'), ('auditor', 'auditor123', 'Auditor')]])
        for user in c.execute('SELECT id,password FROM users').fetchall():
            if user['password'] and not user['password'].startswith(('scrypt:', 'pbkdf2:')):
                c.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(user['password']), user['id']))
        if c.execute('SELECT COUNT(*) FROM assets').fetchone()[0] == 0:
            c.executemany('INSERT INTO assets(code,name,description,category,location,owner,criticality) VALUES(?,?,?,?,?,?,?)', ASSETS)
        if c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0] == 0:
            amap = {r['name']: r['id'] for r in c.execute('SELECT id,name FROM assets')}
            c.executemany('INSERT INTO vulnerabilities(code,title,kind,severity,asset_id,source,state,description) VALUES(?,?,?,?,?,?,?,?)', [(code, title, kind, sev, amap.get(asset), src, 'Potencial', 'Registro precargado a partir de la tabla de vulnerabilidades del documento; requiere validación documental, no implica comprobación en infraestructura municipal.') for code, title, kind, sev, asset, src in VULNS])
        if c.execute('SELECT COUNT(*) FROM threats').fetchone()[0] == 0:
            c.executemany('INSERT INTO threats(name,description,source) VALUES(?,?,?)', THREATS)
        if c.execute('SELECT COUNT(*) FROM policies').fetchone()[0] == 0:
            c.executemany('INSERT INTO policies(name,description,status) VALUES(?,?,?)', POLICIES)
    c.commit()
    c.close()

def band(s):
    return 'Bajo' if s <= 4 else 'Medio' if s <= 9 else 'Alto' if s <= 16 else 'Crítico'

def can_edit():
    return session.get('role') in ('Administrador', 'Analista')

def guard():
    if not session.get('username'):
        return redirect(url_for('login'))
    return None

@app.route('/login', methods=['GET', 'POST'])


