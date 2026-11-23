#!/bin/bash
# ═══════════════════════════════════════════════════════
#  NetControl - Pemasang macOS
#  Memasang .NET 8 SDK, libpcap, dan membangun proyek
# ═══════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║     NetControl - Pemasang macOS      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Check Homebrew ──
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}[!] Homebrew tidak ditemukan. Memasang...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    echo -e "${GREEN}[OK] Homebrew terpasang.${NC}"
else
    echo -e "${GREEN}[OK] Homebrew ditemukan.${NC}"
fi

# ── Install libpcap (usually pre-installed on macOS) ──
echo -e "${YELLOW}[1/3] Memeriksa libpcap...${NC}"
if [ -f "/usr/lib/libpcap.dylib" ] || [ -f "/usr/local/lib/libpcap.dylib" ] || [ -f "/opt/homebrew/lib/libpcap.dylib" ]; then
    echo -e "${GREEN}[OK] libpcap ditemukan (sudah terpasang).${NC}"
else
    echo -e "${YELLOW}    Memasang libpcap melalui Homebrew...${NC}"
    brew install libpcap
    echo -e "${GREEN}[OK] libpcap terpasang.${NC}"
fi

# ── Install .NET 8 SDK ──
echo -e "${YELLOW}[2/3] Memeriksa .NET 8 SDK...${NC}"
if command -v dotnet &> /dev/null && dotnet --list-sdks 2>/dev/null | grep -q "^8\."; then
    echo -e "${GREEN}[OK] .NET 8 SDK sudah terpasang.${NC}"
else
    echo -e "${YELLOW}    Memasang .NET 8 SDK melalui Homebrew...${NC}"
    brew install --cask dotnet-sdk
    echo -e "${GREEN}[OK] .NET 8 SDK terpasang.${NC}"
fi

# ── Build project ──
echo -e "${YELLOW}[3/3] Membangun NetControl...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/NetControl"
dotnet restore
dotnet build --configuration Release

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Instalasi selesai!              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "Jalankan ${CYAN}./start_mac.sh${NC} untuk membuka NetControl."
echo -e "${YELLOW}Catatan: Memerlukan sudo untuk akses jaringan.${NC}"
