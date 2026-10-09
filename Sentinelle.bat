@echo off
setlocal
cd /d "%~dp0"
where pyw.exe >nul 2>nul
if errorlevel 1 (
  where pythonw.exe >nul 2>nul
  if errorlevel 1 (
    echo Python pour Windows est introuvable. Installez Python 3.11 ou plus recent.
    pause
    exit /b 1
  )
  start "" pythonw.exe "%~dp0Surveillance processus.pyw"
) else (
  start "" pyw.exe "%~dp0Surveillance processus.pyw"
)
endlocal
