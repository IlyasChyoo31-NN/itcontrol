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

echo [-] Menghentikan proses background agent...
taskkill /f /im ITOpsAgent.exe >nul 2>&1
taskkill /f /im pythonw.exe >nul 2>&1

echo [-] Menghapus pendaftaran Windows Task Scheduler...
schtasks /delete /tn "ITOpsAgentTask" /f >nul 2>&1

echo [-] Menghapus direktori program C:\Program Files\ITOpsAgent...
if exist "C:\Program Files\ITOpsAgent" (
    rmdir /s /q "C:\Program Files\ITOpsAgent"
)

echo.
echo ========================================================
echo [SUKSES] Agent berhasil dicopot dari laptop ini.
echo ========================================================
pause
