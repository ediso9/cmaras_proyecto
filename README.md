# RiskVision Miraflores — Prototipo del sistema de gestión de riesgos de ciberseguridad

**Proyecto:** Videovigilancia basada en IA — Municipalidad de Miraflores  
**Tipo:** prototipo académico local de gestión de riesgos; no es un SGSI certificado.

## Inicio rápido en Windows

### Opción recomendada: iniciar con doble clic

1. Extrae todos los archivos del ZIP en una carpeta, por ejemplo `C:\RiskVision_Miraflores`.
2. Abre esa carpeta. En ella debes ver `app.py`, `requirements.txt`, `INICIAR_PROTOTIPO.bat`, y las carpetas `templates` y `static`.
3. Haz doble clic en `INICIAR_PROTOTIPO.bat`. El script crea el entorno virtual si hace falta, instala las dependencias y ejecuta la aplicación.
4. Abre `http://127.0.0.1:5000` en el navegador.
5. Para detener el sistema, vuelve a la ventana negra y pulsa `Ctrl+C`.

### Opción PowerShell

Abre PowerShell **en la misma carpeta donde está `app.py`**. Compruébalo con `dir app.py`.

```powershell
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Si ya existe `venv`, no vuelvas a crear el entorno; ejecuta solo la activación, la instalación de dependencias si es necesaria y `python app.py`.

## Usuarios de demostración

- Administrador: `admin` / `admin123`
- Analista: `analista` / `analista123`
- Auditor (solo lectura): `auditor` / `auditor123`

Las contraseñas de demostración se almacenan con hash de Werkzeug. No uses estas credenciales en producción ni publiques el servidor en internet.

## Módulos del prototipo

1. **Dashboard:** resumen de activos, vulnerabilidades, amenazas, riesgos, PRT, riesgo promedio, índice de soberanía, disponibilidad simulada, alertas críticas y tratamientos vencidos; matriz de calor 5×5.
2. **Activos:** inventario de referencia de ocho activos: Cámaras IP (1399, dato documental por validar), cámaras PTZ, Plataforma IA, servidores, red, base de datos, accesos remotos y Central Alerta Miraflores. Permite registrar ubicación, responsable, criticidad y marcar si se evaluó con evidencia.
3. **Vulnerabilidades:** siete registros iniciales, tipo, severidad, fuente obligatoria y estado Potencial/Comprobada. Los registros precargados no confirman una falla real.
4. **Amenazas:** catálogo de acceso no autorizado, malware, fuerza bruta, denegación de servicio (DoS) e interceptación de tráfico.
5. **Evaluación de riesgos:** cada riesgo vincula vulnerabilidad y amenaza. Calcula `R = P × max(C, I, D)`, donde probabilidad y los impactos de confidencialidad, integridad y disponibilidad se valoran de 1 a 5. Opciones de tratamiento: Mitigar, Transferir, Evitar y Aceptar.
6. **Tratamientos:** página separada con acción, responsable, fechas, estado y control ISO/IEC 27002 asociado.
7. **Indicadores:** PAE, PRT, porcentaje de vulnerabilidades tratadas, riesgo promedio, disponibilidad simulada y cumplimiento de políticas; cada indicador muestra su fórmula.
8. **Soberanía digital:** cuestionario por activo/proveedor en cuatro dimensiones: control tecnológico, administración de datos, dependencia de proveedores y continuidad operativa; escala 0–2 e índice porcentual descriptivo.
9. **Cámaras simuladas:** comprobación automática del estado virtual, alertas por desconexión simulada, cierre al recuperar disponibilidad y conversión de alertas en riesgos de referencia.
10. **Cumplimiento normativo:** lista de revisión de ISO/IEC 27002:2022, Ley 29733, Decreto Legislativo 1412 y Ley 30120. Los estados son una revisión documental, no certificación.
11. **Reportes:** resumen de registros, impresión/guardar como PDF desde el navegador y exportación CSV por módulo.

## Flujo principal

**Activos → Vulnerabilidades → Amenazas → Evaluación de riesgos → Tratamientos → Indicadores → Reportes.**  
Soberanía digital, cámaras simuladas y cumplimiento normativo complementan el flujo principal.

## Historias de usuario principales

- **HU01 — Registrar activos.** Como analista de ciberseguridad quiero registrar activos para identificar elementos críticos del ecosistema. **Aceptación:** el registro se almacena y se muestra correctamente.
- **HU02 — Registrar vulnerabilidades.** Como analista quiero registrar vulnerabilidades para evaluar exposiciones. **Aceptación:** el registro se almacena y se muestra correctamente.
- **HU03 — Registrar amenazas.** Como analista quiero documentar amenazas para relacionarlas con vulnerabilidades. **Aceptación:** el registro se almacena y se muestra correctamente.
- **HU04 — Calcular riesgos.** Como analista quiero calcular riesgos mediante probabilidad por impacto para priorizar acciones. **Aceptación:** el cálculo y el registro se almacenan y se muestran correctamente.
- **HU05 — Gestionar tratamientos.** Como responsable quiero registrar tratamientos para mitigar riesgos. **Aceptación:** el tratamiento se almacena y se muestra correctamente.
- **HU06 — Analizar soberanía digital.** Como gestor quiero evaluar control tecnológico, datos y proveedores. **Aceptación:** la evaluación se almacena y se muestra correctamente.

## Escalas y fórmulas

- Niveles: Bajo 1–4, Medio 5–9, Alto 10–16, Crítico 17–25.
- Impacto efectivo = `max(C, I, D)`; riesgo = `P × impacto efectivo`.
- PAE = (activos marcados como evaluados / total de activos) × 100.
- PRT = (riesgos con al menos un tratamiento completado / total de riesgos evaluados) × 100.
- Vulnerabilidades tratadas = (vulnerabilidades con un riesgo completado asociado / total de vulnerabilidades registradas) × 100.
- Riesgo promedio = suma de puntajes / cantidad de riesgos evaluados.
- Disponibilidad simulada = (comprobaciones simuladas con respuesta / comprobaciones simuladas totales) × 100.
- Índice de soberanía descriptivo = (suma de puntajes registrados / (número de respuestas × 2)) × 100. Un índice alto no certifica soberanía real.
- Cumplimiento de políticas = (políticas marcadas “Cumple” / políticas registradas) × 100.

## Alcance y limitaciones

La validación funcional del módulo de disponibilidad se realiza en un entorno de laboratorio simulado, mediante cámaras virtuales y estados de respuesta controlados. El sistema no se conecta a cámaras reales, no recibe ni procesa video, no ejecuta análisis de IA, no hace ping real, no escanea redes ni realiza pruebas de penetración. No accede a datos reales de la Municipalidad de Miraflores. Los activos, amenazas y vulnerabilidades precargados son referencias de trabajo que requieren validación documental; no prueban incidentes ni debilidades reales. Los controles ISO/IEC 27002 deben revisarse con la edición normativa y las evidencias aplicables.

## Base de datos

Por defecto, al iniciar se crea `riskvision.db` en la misma carpeta que `app.py`. Para conectar Supabase, copia `.env.example` como `.env`, completa `SUPABASE_DB_PASSWORD` con la contraseña PostgreSQL configurada en Supabase y define una `FLASK_SECRET_KEY` aleatoria generada localmente. El host, puerto, base y usuario corresponden a los datos de conexión compartidos. También puedes usar `DATABASE_URL` del panel (Database > Connect) en vez de las variables `SUPABASE_DB_*`; debe incluir `sslmode=require`. Si tu red lo necesita, usa la conexión Session Pooler. No uses `SUPABASE_SECRET_KEY` como contraseña ni la publiques.

Si quieres trasladar los datos locales existentes, configura `.env` y ejecuta primero `venv\Scripts\python.exe migrar_a_supabase.py`. El migrador conserva los identificadores y relaciones, y se detiene si detecta registros en las tablas remotas para evitar duplicados o sobrescrituras. Después inicia la aplicación normalmente con `INICIAR_PROTOTIPO.bat`; si `DATABASE_URL` está definida, Flask usará PostgreSQL, y si no, seguirá usando SQLite local.

La clave `SUPABASE_SECRET_KEY` que se compartió durante la configuración debe revocarse/rotarse desde el panel de Supabase. Esta aplicación se conecta directamente a PostgreSQL y no necesita publicar esa clave ni la publishable key en el servidor.
