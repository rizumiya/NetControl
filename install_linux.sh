#!/bin/bash
# ═══════════════════════════════════════════════════════
#  NetControl - Pemasang Linux
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
echo "║     NetControl - Pemasang Linux      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Detect package manager ──
if command -v apt &> /dev/null; then
    PKG_MGR="apt"
elif command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &> /dev/null; then
    PKG_MGR="pacman"
else
    echo -e "${RED}[GALAT] Tidak ditemukan pengelola paket yang didukung (apt/dnf/pacman).${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Pengelola paket: ${PKG_MGR}${NC}"

# ── Install libpcap ──
echo -e "${YELLOW}[1/3] Memasang libpcap...${NC}"
case $PKG_MGR in
    apt)
        sudo apt update -qq
        sudo apt install -y libpcap-dev
        ;;
    dnf)
        sudo dnf install -y libpcap-devel
        ;;
    pacman)
        sudo pacman -Sy --noconfirm libpcap
        ;;
esac
echo -e "${GREEN}[OK] libpcap terpasang.${NC}"

# ── Install .NET 8 SDK ──
echo -e "${YELLOW}[2/3] Memeriksa .NET 8 SDK...${NC}"
if command -v dotnet &> /dev/null && dotnet --list-sdks 2>/dev/null | grep -q "^8\."; then
    echo -e "${GREEN}[OK] .NET 8 SDK sudah terpasang.${NC}"
else
    echo -e "${YELLOW}    Memasang .NET 8 SDK...${NC}"
    case $PKG_MGR in
        apt)
            # Try the Ubuntu/Debian package first
            if apt-cache show dotnet-sdk-8.0 &> /dev/null; then
                sudo apt install -y dotnet-sdk-8.0
            else
                # Fallback to snap
                sudo snap install dotnet-sdk --classic
            fi
            ;;
        dnf)
            sudo dnf install -y dotnet-sdk-8.0
            ;;
        pacman)
            sudo pacman -Sy --noconfirm dotnet-sdk-8.0
            ;;
    esac
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
echo -e "Jalankan ${CYAN}./start_linux.sh${NC} untuk membuka NetControl."
echo -e "${YELLOW}Catatan: Memerlukan sudo untuk akses jaringan.${NC}"
