@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Virtual environment not found. Run START_DASHBOARD.bat once first, then run this again.
 pause
 exit /b 1
)
call .venv\Scripts\activate.bat
python agent.py
pause
