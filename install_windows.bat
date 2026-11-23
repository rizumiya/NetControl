@echo off
chcp 65001 >nul
if exist "%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" (
    set "DOTNET_ROOT=%LOCALAPPDATA%\Microsoft\dotnet"
    set "PATH=%LOCALAPPDATA%\Microsoft\dotnet;%PATH%"
)
REM ═══════════════════════════════════════════════════════
REM  NetControl - Pemasang Windows
REM  Memeriksa .NET 8 SDK, Npcap, dan membangun proyek
REM ═══════════════════════════════════════════════════════

echo.
echo ╔══════════════════════════════════════╗
echo ║    NetControl - Pemasang Windows     ║
echo ╚══════════════════════════════════════╝
echo.

REM ── Periksa Hak Administrator ──
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Skrip ini memerlukan hak akses Administrator.
    echo     Klik kanan dan pilih "Run as administrator" ^(Jalankan sebagai administrator^).
    pause
    exit /b 1
)

REM ── Periksa .NET 8 SDK ──
echo [1/3] Memeriksa .NET 8 SDK...
where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    echo [GALAT] .NET 8 SDK tidak ditemukan.
    echo         Unduh dari: https://dotnet.microsoft.com/download/dotnet/8.0
    echo         Pasang SDK ^(bukan hanya Runtime^) lalu jalankan ulang skrip ini.
    echo.
    start https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

dotnet --list-sdks | findstr /R "^8\." >nul 2>&1
if %errorlevel% neq 0 (
    echo [PERINGATAN] .NET 8 SDK tidak ditemukan. Anda memiliki:
    dotnet --list-sdks
    echo.
    echo Unduh .NET 8 SDK dari: https://dotnet.microsoft.com/download/dotnet/8.0
    start https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)
echo [OK] .NET 8 SDK ditemukan.

REM ── Periksa Npcap ──
echo [2/3] Memeriksa Npcap...
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [OK] Npcap ditemukan.
) else if exist "C:\Windows\System32\wpcap.dll" (
    echo [OK] WinPcap/Npcap ditemukan.
) else (
    echo [PERINGATAN] Npcap tidak terdeteksi.
    echo              Unduh dari: https://nmap.org/npcap/
    echo              PENTING: Centang "Install Npcap in WinPcap API-compatible Mode"
    echo.
    start https://nmap.org/npcap/
    echo Setelah memasang Npcap, jalankan ulang skrip ini.
    pause
    exit /b 1
)

REM ── Bangun proyek ──
echo [3/3] Membangun NetControl...
cd /d "%~dp0NetControl"
dotnet restore
dotnet build --configuration Release

if %errorlevel% neq 0 (
    echo [GALAT] Proses build gagal. Periksa kesalahan di atas.
    pause
    exit /b 1
)

echo.
echo ╔══════════════════════════════════════╗
echo ║    Instalasi selesai! [OK]           ║
echo ╚══════════════════════════════════════╝
echo.
echo Jalankan start_windows.bat untuk membuka NetControl.
echo Catatan: Memerlukan hak akses Administrator.
echo.
pause

