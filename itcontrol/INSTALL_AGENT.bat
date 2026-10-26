@echo off
setlocal
cd /d "%~dp0"

:: Cek hak akses Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ========================================================
    echo [ERROR] Harap klik kanan file ini dan pilih:
    echo        "Run as administrator"
    echo ========================================================
    echo.
    pause
    exit /b 1
)

set TARGET_DIR=C:\Program Files\ITOpsAgent
echo [+] Menyiapkan direktori target di %TARGET_DIR%...
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"

echo [+] Menyalin file agent dan konfigurasi...
if exist "%~dp0ITOpsAgent.exe" (
    copy /y "%~dp0ITOpsAgent.exe" "%TARGET_DIR%\"
) else (
    copy /y "%~dp0agent.py" "%TARGET_DIR%\"
)
copy /y "%~dp0agent_config.json" "%TARGET_DIR%\"

echo [+] Mendaftarkan background service ke Windows Task Scheduler...
schtasks /delete /tn "ITOpsAgentTask" /f >nul 2>&1

if exist "%TARGET_DIR%\ITOpsAgent.exe" (
    schtasks /create /tn "ITOpsAgentTask" /tr "\"%TARGET_DIR%\ITOpsAgent.exe\"" /sc onlogon /rl highest /f
) else (
    schtasks /create /tn "ITOpsAgentTask" /tr "pythonw.exe \"%TARGET_DIR%\agent.py\"" /sc onlogon /rl highest /f
)

echo [+] Menjalankan agent sekarang di latar belakang...
schtasks /run /tn "ITOpsAgentTask"

echo.
echo ========================================================
echo [SUKSES] IT Ops Control Tower Agent berhasil dipasang!
echo Agent otomatis aktif di background setiap laptop menyala.
echo ========================================================
pause
