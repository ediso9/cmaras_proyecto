@echo off
setlocal
cd /d "%~dp0"
title RiskVision Miraflores - Prototipo

echo ================================================
echo   RiskVision Miraflores - Inicio del prototipo
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: No se encontro Python en PATH.
  echo Instala Python 3.10 o posterior y marca "Add Python to PATH".
  pause
  exit /b 1
)

if not exist "venv\Scripts\python.exe" (
  echo Creando entorno virtual...
  python -m venv venv
  if errorlevel 1 (
    echo ERROR al crear el entorno virtual.
    pause
    exit /b 1
  )
)

echo Instalando o verificando dependencias...
"venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo ERROR al instalar dependencias. Revisa la conexion a internet.
  pause
  exit /b 1
)

echo.
echo Iniciando RiskVision. Abre http://127.0.0.1:5000 en tu navegador.
echo Para detenerlo, pulsa Ctrl+C en esta ventana.
echo.
"venv\Scripts\python.exe" app.py
if errorlevel 1 (
  echo.
  echo La aplicacion se detuvo por un error. Copia el mensaje para revisarlo.
  pause
)
endlocal
