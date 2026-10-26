@echo off
setlocal
cd /d "%~dp0"
echo IT Operation Control Tower (Django + Tabler.io Edition) - R15
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":5000 .*LISTENING"') do set EXISTING_PID=%%P
if defined EXISTING_PID (
  echo.
  echo WARNING: port 5000 is already occupied by PID %EXISTING_PID%.
  echo The old dashboard may still be running, which would make the browser show the old UI.
  echo Close the previous dashboard terminal or stop that process, then run this launcher again.
  pause
  exit /b 2
)
if not exist ".venv\Scripts\python.exe" py -m venv .venv
call .venv\Scripts\activate.bat
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:5000
pause
