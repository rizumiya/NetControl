@echo off
chcp 65001 >nul
if exist "%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" (
    set "DOTNET_ROOT=%LOCALAPPDATA%\Microsoft\dotnet"
    set "PATH=%LOCALAPPDATA%\Microsoft\dotnet;%PATH%"
)
REM ═══════════════════════════════════════════════════════
REM  NetControl - Peluncur Windows
REM  Menjalankan NetControl sebagai Administrator
REM ═══════════════════════════════════════════════════════

echo.
echo ╔══════════════════════════════════════╗
echo ║    NetControl - Peluncur Windows     ║
echo ╚══════════════════════════════════════╝
echo.

REM ── Periksa Hak Administrator ──
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] NetControl memerlukan hak akses Administrator.
    echo     Membuka ulang sebagai Administrator...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM ── Periksa apakah sudah di-build ──
set "BUILT=0"
if exist "%~dp0NetControl\bin\Release\net8.0\NetControl.dll" set "BUILT=1"
if exist "%~dp0NetControl\bin\Release\net8.0\NetControl.exe" set "BUILT=1"

if "%BUILT%"=="0" (
    echo [GALAT] NetControl belum di-build. Jalankan install_windows.bat terlebih dahulu.
    pause
    exit /b 1
)

REM ── Pastikan IP Forwarding Kernel Windows Nonaktif (relay & throttle ditangani oleh NetControl) ──
echo [1/2] Menyiapkan antarmuka jaringan Windows...
powershell -NoProfile -Command "Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | Set-NetIPInterface -Forwarding Disabled -ErrorAction SilentlyContinue" >nul 2>&1

REM ── Jalankan (jendela CMD akan otomatis tertutup) ──
echo [2/2] Menjalankan NetControl...
if exist "%~dp0NetControl\bin\Release\net8.0\NetControl.exe" (
    start "" /D "%~dp0NetControl\bin\Release\net8.0" "%~dp0NetControl\bin\Release\net8.0\NetControl.exe"
) else (
    start "" /D "%~dp0NetControl\bin\Release\net8.0" dotnet "%~dp0NetControl\bin\Release\net8.0\NetControl.dll"
)
exit /b 0
