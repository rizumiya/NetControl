#!/bin/bash
# ═══════════════════════════════════════════════════════
#  NetControl - Peluncur macOS
#  Mengaktifkan IP forwarding dan menjalankan dengan sudo
# ═══════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/NetControl"
BINARY="$PROJECT_DIR/bin/Release/net8.0/NetControl"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║     NetControl - Peluncur macOS      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Check if built ──
if [ ! -f "$BINARY" ] && [ ! -f "$BINARY.dll" ]; then
    echo -e "${RED}[GALAT] NetControl belum di-build. Jalankan ./install_mac.sh terlebih dahulu.${NC}"
    exit 1
fi

# ── Check for root ──
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] NetControl memerlukan hak akses root untuk mengakses jaringan.${NC}"
    echo -e "${YELLOW}    Menjalankan ulang dengan sudo...${NC}"
    echo ""
    exec sudo bash "$0" "$@"
fi

# ── Enable IP forwarding (required for MITM on macOS) ──
echo -e "${YELLOW}[1/2] Mengaktifkan IP forwarding...${NC}"
CURRENT_FWD=$(sysctl -n net.inet.ip.forwarding)
sysctl -w net.inet.ip.forwarding=1 > /dev/null 2>&1
echo -e "${GREEN}[OK] IP forwarding diaktifkan.${NC}"

# ── Launch ──
echo -e "${YELLOW}[2/2] Menjalankan NetControl...${NC}"
echo ""

cd "$PROJECT_DIR"
dotnet run --configuration Release --no-build
EXIT_CODE=$?

# ── Restore IP forwarding to previous state ──
sysctl -w net.inet.ip.forwarding=$CURRENT_FWD > /dev/null 2>&1
echo -e "${GREEN}[OK] IP forwarding dipulihkan ke status sebelumnya ($CURRENT_FWD).${NC}"

exit $EXIT_CODE
