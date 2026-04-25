"""
android_surface.py — Android Zero-Click Attack Surface Research Module
WiZZA Pentest Toolkit

Targets rooted Android 16+ with KernelSU.
Attack surfaces:
  1. SMS/MMS parser (com.android.mms / Messaging)
  2. Bluetooth stack (BlueDroid / Fluoride / BlueZ)
  3. WiFi driver hooks (cfg80211 / wpa_supplicant)
  4. Binder IPC fuzzing (system_server, mediaserver)
  5. NFC (libnfc-nci)
  6. Media parser (libstagefright / libhevc / libavc)
  7. Intent fuzzing via ADB

Requirements:
  adb, frida-server on device, pip install frida frida-tools

Usage:
  from android_surface import frida_hooks, fuzz_sms, fuzz_mms
  from android_surface import binder_fuzz, full_android_research
"""

import os
import re
import json
import time
import struct
import random
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime

# ── ADB Helper ────────────────────────────────────────────────────────────────

def adb(cmd: str, serial: str = None, timeout: int = 30) -> tuple:
    """Run adb command, returns (returncode, stdout, stderr)."""
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    full = base + cmd.split()
    try:
        proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", "adb not found — install Android platform-tools"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as e:
        return -3, "", str(e)


def adb_shell(cmd: str, serial: str = None, timeout: int = 30) -> str:
    """Run adb shell command, return stdout."""
    rc, out, err = adb(f"shell {cmd}", serial, timeout)
    return out.strip()


def check_device(serial: str = None) -> dict:
    """Check connected Android device info."""
    result = {"connected": False, "serial": serial, "info": {}}

    rc, out, _ = adb("devices", serial)
    if rc != 0:
        return result

    lines = [l for l in out.splitlines() if "\t" in l and "offline" not in l]
    if not lines:
        result["error"] = "No device connected"
        return result

    result["connected"] = True
    result["info"]["android_version"] = adb_shell("getprop ro.build.version.release", serial)
    result["info"]["model"]           = adb_shell("getprop ro.product.model", serial)
    result["info"]["build"]           = adb_shell("getprop ro.build.display.id", serial)
    result["info"]["rooted"]          = "root" in adb_shell("id", serial).lower()
    result["info"]["kernelsu"]        = "kernelsu" in adb_shell(
        "getprop ro.kernelsu.version", serial).lower() or os.path.exists("/dev/ksud")

    return result


# ── Frida Hook Scripts ────────────────────────────────────────────────────────

def frida_hooks(target: str = "all") -> dict:
    """
    Generate Frida hook scripts for Android attack surface instrumentation.
    Deploy with: frida -U -f <package> -l <script.js> --no-pause

    targets: sms, mms, bluetooth, media, nfc, binder, all
    """
    scripts = {}

    # ── SMS/MMS Parser Hooks ──────────────────────────────────────────────────
    scripts["sms"] = """
/* Android SMS/MMS Parser Hooks — WiZZA Android Surface Research
 * Hooks MMS parser in com.android.mms and system MMS stack
 * Usage: frida -U -f com.android.mms -l sms_hooks.js --no-pause
 */

Java.perform(function() {
    console.log('[WiZZA] SMS/MMS hooks starting');

    // Hook PDU parsing (raw SMS bytes → decoded message)
    try {
        var SmsMessage = Java.use('android.telephony.SmsMessage');
        SmsMessage.createFromPdu.overload('[B', 'java.lang.String').implementation =
            function(pdu, format) {
                console.log('[SMS-PDU] format=' + format + ' len=' + pdu.length);
                // Log raw PDU bytes (first 64)
                var hex = Array.from(pdu).slice(0, 64)
                    .map(b => ('00' + (b & 0xFF).toString(16)).slice(-2)).join(' ');
                console.log('[SMS-PDU] bytes: ' + hex);
                var result = this.createFromPdu(pdu, format);
                if (result) {
                    console.log('[SMS-PDU] from=' + result.getOriginatingAddress());
                    console.log('[SMS-PDU] body=' + result.getMessageBody());
                }
                return result;
            };
        console.log('[+] SmsMessage.createFromPdu hooked');
    } catch(e) { console.log('[-] SmsMessage hook: ' + e); }

    // Hook MMS transaction (PDU decode)
    try {
        var PduParser = Java.use('com.google.android.mms.pdu.PduParser');
        PduParser.parse.overload().implementation = function() {
            console.log('[MMS-PDU] PduParser.parse() called');
            var pdu = this.mPduDataStream;
            var result = this.parse();
            console.log('[MMS-PDU] parsed type: ' + (result ? result.getMessageType() : 'null'));
            return result;
        };
        console.log('[+] PduParser.parse hooked');
    } catch(e) { console.log('[-] PduParser hook: ' + e); }

    // Hook MMS attachment processing
    try {
        var PduBody = Java.use('com.google.android.mms.pdu.PduBody');
        PduBody.addPart.implementation = function(part) {
            var ct = part.getContentType();
            var name = part.getName();
            var data = part.getData();
            console.log('[MMS-PART] contentType=' + (ct ? new java.lang.String(ct) : 'null'));
            console.log('[MMS-PART] name=' + (name ? new java.lang.String(name) : 'null'));
            console.log('[MMS-PART] dataLen=' + (data ? data.length : 0));
            return this.addPart(part);
        };
        console.log('[+] PduBody.addPart hooked');
    } catch(e) { console.log('[-] PduBody hook: ' + e); }

    // Monitor for crashes/exceptions in SMS stack
    Java.use('java.lang.Runtime').exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('sms') >= 0 || cmd.indexOf('mms') >= 0) {
            console.log('[EXEC] ' + cmd);
        }
        return this.exec(cmd);
    };

    console.log('[WiZZA] SMS/MMS hooks active — send test messages to trigger');
});
"""

    # ── Bluetooth Stack Hooks ─────────────────────────────────────────────────
    scripts["bluetooth"] = """
/* Android Bluetooth Stack Hooks — WiZZA Android Surface Research
 * Hooks BlueDroid/Fluoride BT stack
 * Usage: frida -U -n com.android.bluetooth -l bt_hooks.js
 */

Java.perform(function() {
    console.log('[WiZZA] Bluetooth hooks starting');

    // Hook incoming BT data (L2CAP / RFCOMM level)
    try {
        var BluetoothSocket = Java.use('android.bluetooth.BluetoothSocket');

        BluetoothSocket.read.overload('[B', 'int', 'int').implementation =
            function(buf, offset, length) {
                var n = this.read(buf, offset, length);
                if (n > 0) {
                    var hex = Array.from(buf).slice(offset, offset + Math.min(n, 32))
                        .map(b => ('00' + (b & 0xFF).toString(16)).slice(-2)).join(' ');
                    console.log('[BT-READ] ' + n + ' bytes: ' + hex);
                }
                return n;
            };
        console.log('[+] BluetoothSocket.read hooked');
    } catch(e) { console.log('[-] BluetoothSocket hook: ' + e); }

    // Hook OBEX (file transfer over BT)
    try {
        var OBEXSession = Java.use('javax.obex.ClientSession');
        OBEXSession.put.implementation = function(op) {
            console.log('[OBEX] PUT operation: ' + op);
            return this.put(op);
        };
    } catch(e) {}

    // Hook BT pairing (PIN/OOB)
    try {
        var BluetoothDevice = Java.use('android.bluetooth.BluetoothDevice');
        BluetoothDevice.setPairingConfirmation.implementation = function(confirm) {
            console.log('[BT-PAIR] setPairingConfirmation: ' + confirm);
            return this.setPairingConfirmation(confirm);
        };
        console.log('[+] BluetoothDevice pairing hooked');
    } catch(e) { console.log('[-] BT pairing hook: ' + e); }

    // Monitor native BT library (libbluetooth.so)
    var libbluetooth = Process.findModuleByName("libbluetooth.so") ||
                       Process.findModuleByName("libbluetooth_jni.so");
    if (libbluetooth) {
        console.log('[+] libbluetooth found at: ' + libbluetooth.base);

        // Hook l2cap_data_ind (L2CAP data indication — all BT data flows through here)
        var l2cap_fn = libbluetooth.base.add(0x0); // offset needs symbols
        // In practice: use `nm -D libbluetooth.so | grep l2cap`
        console.log('[*] Use: frida-trace -U -n com.android.bluetooth -i "l2cap*"');
    }

    console.log('[WiZZA] Bluetooth hooks active');
});
"""

    # ── Media Parser Hooks (Stagefright) ─────────────────────────────────────
    scripts["media"] = """
/* Android Media Parser Hooks — WiZZA Android Surface Research
 * Hooks libstagefright, MediaCodec, BitmapFactory
 * MMS attachments are decoded through these parsers
 */

Java.perform(function() {
    console.log('[WiZZA] Media parser hooks starting');

    // Hook BitmapFactory — decodes images in MMS/notifications
    try {
        var BitmapFactory = Java.use('android.graphics.BitmapFactory');
        BitmapFactory.decodeByteArray.overload('[B', 'int', 'int').implementation =
            function(data, offset, length) {
                console.log('[BITMAP] decodeByteArray: ' + length + ' bytes');
                var hex = Array.from(data).slice(0, 8)
                    .map(b => ('00' + (b & 0xFF).toString(16)).slice(-2)).join(' ');
                console.log('[BITMAP] magic: ' + hex);
                return this.decodeByteArray(data, offset, length);
            };
        console.log('[+] BitmapFactory.decodeByteArray hooked');
    } catch(e) { console.log('[-] BitmapFactory hook: ' + e); }

    // Hook MediaCodec (video/audio parser)
    try {
        var MediaCodec = Java.use('android.media.MediaCodec');
        MediaCodec.configure.overload(
            'android.media.MediaFormat',
            'android.view.Surface',
            'android.media.MediaCrypto',
            'int'
        ).implementation = function(format, surface, crypto, flags) {
            console.log('[CODEC] configure: mime=' + format.getString('mime'));
            return this.configure(format, surface, crypto, flags);
        };
        console.log('[+] MediaCodec.configure hooked');
    } catch(e) { console.log('[-] MediaCodec hook: ' + e); }

    // Hook native crash handler
    Process.setExceptionHandler(function(details) {
        console.log('[CRASH] ' + JSON.stringify(details));
    });

    console.log('[WiZZA] Media hooks active');
});
"""

    # ── Binder IPC Fuzzing Hooks ──────────────────────────────────────────────
    scripts["binder"] = """
/* Android Binder IPC Hooks — WiZZA Android Surface Research
 * Monitors system_server Binder transactions
 */

Java.perform(function() {
    console.log('[WiZZA] Binder IPC hooks starting');

    // Hook Parcel reading (all IPC data is Parcel-serialized)
    try {
        var Parcel = Java.use('android.os.Parcel');

        Parcel.readString.implementation = function() {
            var s = this.readString();
            if (s && s.length > 0 && s.length < 200) {
                // Log interesting strings (avoid flooding)
                if (s.indexOf('://') >= 0 || s.indexOf('/data/') >= 0) {
                    console.log('[BINDER-STR] ' + s);
                }
            }
            return s;
        };

        Parcel.createException.implementation = function(code, msg) {
            console.log('[BINDER-EXC] code=' + code + ' msg=' + msg);
            return this.createException(code, msg);
        };
        console.log('[+] Parcel hooks active');
    } catch(e) { console.log('[-] Parcel hook: ' + e); }

    // Hook IBinder.transact
    try {
        var Binder = Java.use('android.os.Binder');
        Binder.transact.overload('int', 'android.os.Parcel', 'android.os.Parcel', 'int')
            .implementation = function(code, data, reply, flags) {
                // Log high transaction codes (often custom, less validated)
                if (code > 10) {
                    console.log('[BINDER-TX] code=' + code + ' flags=' + flags);
                }
                return this.transact(code, data, reply, flags);
            };
        console.log('[+] Binder.transact hooked');
    } catch(e) { console.log('[-] Binder.transact: ' + e); }

    console.log('[WiZZA] Binder hooks active');
});
"""

    scripts["all"] = "\n\n".join([
        "// === WiZZA Combined Android Surface Hooks ===",
        scripts["sms"],
        scripts["bluetooth"],
        scripts["media"],
        scripts["binder"],
    ])

    if target == "all":
        return scripts
    return {target: scripts.get(target, "")}


# ── SMS Fuzzing ────────────────────────────────────────────────────────────────

def fuzz_sms(target_number: str, count: int = 50,
             serial: str = None) -> dict:
    """
    Fuzz SMS parser by sending crafted SMS via ADB (requires USB + SIM).
    Uses Android's SmsManager to send malformed PDUs to self or target.
    """
    result = {"sent": 0, "errors": [], "payloads": []}

    # Generate SMS fuzzing payloads
    payloads = []

    # 1. Maximum length messages
    payloads.append(("max_length", "A" * 160))
    payloads.append(("max_length_unicode", "\u0041" * 70))

    # 2. Special characters
    payloads.append(("null_bytes", "Hello\x00World\x00"))
    payloads.append(("format_string", "%s%s%s%s%n%n%d%d"))
    payloads.append(("rtl_override", "\u202e" + "Evil Text"))  # RTL override
    payloads.append(("zero_width", "\u200b\u200c\u200d" * 20))

    # 3. Emoji/unicode edge cases
    payloads.append(("surrogate_pair", "\ud83d\ude00" * 20))
    payloads.append(("invalid_utf8", "Test\xff\xfe\xfd"))

    # 4. Class 0 (flash SMS — displays immediately, no storage)
    payloads.append(("flash_sms", "FLASH:" + "A" * 140))

    # 5. Port-addressed SMS (WAP push, OTA — bypasses normal SMS app)
    payloads.append(("wap_push", "\x01\x06\x25\x00\x01\x01\x00"))

    for name, msg in payloads[:count]:
        # Send via ADB SmsManager (works on own device)
        script = f"""
am broadcast -a android.provider.Telephony.SMS_RECEIVED \
  --es address "{target_number}" \
  --es body "{msg.encode('unicode_escape').decode()}" \
  com.android.mms
"""
        rc, out, err = adb(f'shell {script.strip()}', serial)
        payload_result = {
            "name":   name,
            "length": len(msg),
            "rc":     rc,
            "output": out[:100],
        }
        result["payloads"].append(payload_result)
        if rc == 0:
            result["sent"] += 1
        else:
            result["errors"].append(f"{name}: {err[:100]}")
        time.sleep(0.5)

    return result


# ── MMS Fuzzing ────────────────────────────────────────────────────────────────

def fuzz_mms(serial: str = None,
             out_dir: str = "/tmp/wizza_android_mms") -> dict:
    """
    Generate malformed MMS PDUs and deliver via ADB broadcast.
    Tests MMS PDU parser in Android messaging stack.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    result = {"payloads_generated": 0, "pushed": 0, "errors": []}

    def make_mms_pdu(variant: str) -> bytes:
        """Create malformed MMS PDU."""
        # MMS PDU header: M-Send.req
        # X-Mms-Message-Type: 128 (0x80) = m-send-req

        if variant == "overflow_from":
            # Overflow the From header field
            from_val   = b'A' * 4096 + b'/TYPE=PLMN'
            hdr = bytes([0x8C, 0x80,   # X-Mms-Message-Type: m-send-req
                         0x98, 0x01,   # X-Mms-Transaction-Id: 1
                         0x8D, 0x92,   # X-Mms-Mms-Version: 1.2
                         0x89])        # X-Mms-From
            return hdr + struct.pack('>H', len(from_val)) + from_val

        elif variant == "negative_content_length":
            return bytes([
                0x8C, 0x80,       # M-Send.req
                0x8E, 0xFF, 0xFF, 0xFF, 0xFF,  # Content-Length: max uint32
                0x00              # Content start
            ])

        elif variant == "recursive_multipart":
            # multipart/mixed containing itself (causes infinite recursion)
            boundary = b'--boundary\r\n'
            content_type = b'Content-Type: multipart/mixed; boundary="boundary"\r\n\r\n'
            return bytes([0x8C, 0x80]) + boundary + content_type + boundary * 100

        elif variant == "zero_length_body":
            return bytes([0x8C, 0x84,   # M-Retrieve.conf
                          0x98, 0x01,
                          0x8D, 0x92,
                          0x84, 0x01, 0x80,  # Status: Retrieved
                          0x00])  # Empty body

        elif variant == "type_confusion":
            # Claim content-type is image but send PDF bytes
            pdf_magic = b'%PDF-1.4\n'
            hdr = bytes([0x8C, 0x80,
                         0x84])  # Content-Type
            ct = b'image/jpeg'
            return hdr + bytes([len(ct)]) + ct + pdf_magic

        return bytes([0x8C, 0x80, 0x00])

    for variant in ["overflow_from", "negative_content_length",
                    "recursive_multipart", "zero_length_body", "type_confusion"]:
        pdu = make_mms_pdu(variant)
        pdu_path = os.path.join(out_dir, f"mms_{variant}.pdu")
        with open(pdu_path, "wb") as f:
            f.write(pdu)
        result["payloads_generated"] += 1

        # Push to device and trigger processing
        device_path = f"/data/local/tmp/wizza_mms_{variant}.pdu"
        rc, _, _ = adb(f"push {pdu_path} {device_path}", serial)
        if rc == 0:
            # Trigger MMS processing via intent
            adb(f'shell am broadcast -a android.provider.Telephony.WAP_PUSH_RECEIVED '
                f'--es wappushdata {device_path} '
                f'-n com.android.mms/.transaction.SmsReceiver', serial)
            result["pushed"] += 1
        else:
            result["errors"].append(f"{variant}: push failed")

    return result


# ── Crash Monitor ─────────────────────────────────────────────────────────────

def monitor_crashes(duration: int = 120, serial: str = None) -> dict:
    """
    Monitor logcat for crashes during fuzzing session.
    Focuses on: SIGSEGV, SIGABRT, stack smashing, use-after-free indicators.
    """
    result = {
        "duration":  duration,
        "crashes":   [],
        "start":     datetime.now().isoformat(),
    }

    print(f"[*] Monitoring Android crashes for {duration}s...")

    target_processes = [
        "com.android.mms", "com.google.android.mms",
        "com.android.bluetooth", "com.android.phone",
        "system_server", "mediaserver", "nfc",
        "wpa_supplicant", "surfaceflinger",
    ]

    crash_patterns = [
        r'SIGSEGV',
        r'SIGABRT',
        r'stack corruption',
        r'use-after-free',
        r'heap-buffer-overflow',
        r'FATAL EXCEPTION',
        r'AndroidRuntime.*FATAL',
        r'art.*FATAL',
        r'\bcrash\b',
    ]

    # Start logcat in background
    logcat_cmd = ["adb"]
    if serial:
        logcat_cmd += ["-s", serial]
    logcat_cmd += ["logcat", "-v", "threadtime", "*:E"]

    try:
        proc = subprocess.Popen(
            logcat_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        end_time = time.time() + duration
        while time.time() < end_time:
            line = proc.stdout.readline()
            if not line:
                break

            # Check for crash patterns
            for pattern in crash_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if it's a target process
                    is_target = any(p in line for p in target_processes)
                    crash_entry = {
                        "time":      datetime.now().isoformat(),
                        "line":      line.strip()[:200],
                        "pattern":   pattern,
                        "is_target": is_target,
                    }
                    result["crashes"].append(crash_entry)
                    flag = "🔴 TARGET" if is_target else "⚪"
                    print(f"  {flag} CRASH: {line.strip()[:100]}")
                    break

        proc.terminate()

    except FileNotFoundError:
        result["error"] = "adb not found"
    except Exception as e:
        result["error"] = str(e)

    result["total"]   = len(result["crashes"])
    result["targets"] = [c for c in result["crashes"] if c["is_target"]]
    result["end"]     = datetime.now().isoformat()

    return result


# ── Intent Fuzzing ────────────────────────────────────────────────────────────

def fuzz_intents(package: str = "com.android.mms",
                 serial: str = None) -> dict:
    """
    Fuzz exported Android intents via ADB.
    Targets exported Activities, Services, and BroadcastReceivers.
    """
    result = {"package": package, "sent": 0, "crashes": [], "errors": []}

    # Get exported components
    rc, dump, _ = adb(f"shell dumpsys package {package}", serial)
    activities = re.findall(r'(\S+Activity)\s+filter', dump)
    receivers  = re.findall(r'Receiver\s+Permissions.*?(\S+)', dump)

    fuzz_extras = [
        "",
        "--es data 'A'*1000",
        "--ei id -1",
        "--ei id 2147483647",
        "--ez flag true",
        "--eu uri 'file:///etc/passwd'",
        "--eu uri 'content://contacts/people/'",
        "--eu uri '../../../data/data/' ",
        "--es path '/../../../../etc/shadow'",
    ]

    for component in (activities + receivers)[:10]:
        for extras in fuzz_extras:
            cmd = f"shell am start -n {package}/{component} {extras} 2>&1"
            rc, out, _ = adb(cmd, serial, timeout=5)
            result["sent"] += 1
            if "crash" in out.lower() or "exception" in out.lower():
                result["crashes"].append({
                    "component": component,
                    "extras":    extras,
                    "output":    out[:200],
                })
            time.sleep(0.1)

    return result


# ── Deploy Frida Server ────────────────────────────────────────────────────────

def deploy_frida_server(arch: str = "arm64",
                        version: str = "16.2.1",
                        serial: str = None) -> dict:
    """
    Download and deploy Frida server to rooted Android device.
    """
    result = {"deployed": False, "version": version, "error": None}

    # Check if already running
    out = adb_shell("pidof frida-server", serial)
    if out.strip().isdigit():
        result["deployed"] = True
        result["pid"]      = out.strip()
        return result

    frida_binary = f"frida-server-{version}-android-{arch}"
    frida_url    = (f"https://github.com/frida/frida/releases/download/"
                    f"{version}/{frida_binary}.xz")

    local_path  = f"/tmp/{frida_binary}"
    device_path = "/data/local/tmp/frida-server"

    # Download
    if not os.path.exists(local_path):
        try:
            subprocess.run(["wget", "-q", frida_url, "-O", local_path + ".xz"],
                           timeout=120, check=True)
            subprocess.run(["xz", "-d", local_path + ".xz"], check=True)
        except Exception as e:
            result["error"] = f"Download failed: {e}"
            return result

    # Push to device
    rc, _, err = adb(f"push {local_path} {device_path}", serial)
    if rc != 0:
        result["error"] = f"Push failed: {err}"
        return result

    # Set executable and run
    adb(f"shell chmod 755 {device_path}", serial)
    subprocess.Popen(
        (["adb"] + (["-s", serial] if serial else []) +
         ["shell", "su", "-c", f"{device_path} &"]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    out = adb_shell("pidof frida-server", serial)
    result["deployed"] = out.strip().isdigit()
    result["pid"]      = out.strip()
    return result


# ── Full Android Research Session ─────────────────────────────────────────────

def full_android_research(target_number: str = None,
                          serial: str = None,
                          duration: int = 120) -> dict:
    """
    Full automated Android zero-click research session.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "device":    {},
        "frida":     {},
        "sms_fuzz":  {},
        "mms_fuzz":  {},
        "crashes":   {},
        "findings":  [],
    }

    print("[*] Android zero-click research session")

    print("\n[1/5] Device check...")
    result["device"] = check_device(serial)
    if not result["device"]["connected"]:
        print("  [-] No device — connect Android via USB with USB debugging enabled")
        return result
    print(f"  [+] {result['device']['info'].get('model')} "
          f"Android {result['device']['info'].get('android_version')}")

    print("\n[2/5] Deploying Frida server...")
    result["frida"] = deploy_frida_server(serial=serial)
    if result["frida"]["deployed"]:
        print(f"  [+] Frida server running (PID {result['frida'].get('pid')})")

        # Save hook scripts
        hooks = frida_hooks("all")
        for name, script in hooks.items():
            spath = f"/tmp/wizza_frida_{name}.js"
            with open(spath, "w") as f:
                f.write(script)
        print(f"  [+] Frida scripts saved to /tmp/wizza_frida_*.js")
    else:
        print(f"  [-] Frida deploy failed: {result['frida'].get('error')}")

    print("\n[3/5] SMS fuzzing...")
    if target_number:
        result["sms_fuzz"] = fuzz_sms(target_number, serial=serial)
        print(f"  Sent {result['sms_fuzz']['sent']} SMS payloads")

    print("\n[4/5] MMS fuzzing...")
    result["mms_fuzz"] = fuzz_mms(serial=serial)
    print(f"  Generated {result['mms_fuzz']['payloads_generated']} MMS PDUs, "
          f"pushed {result['mms_fuzz']['pushed']}")

    print(f"\n[5/5] Crash monitoring ({duration}s)...")
    result["crashes"] = monitor_crashes(duration, serial)

    # Analyze findings
    for crash in result["crashes"].get("targets", []):
        result["findings"].append({
            "severity": "HIGH",
            "type":     "target_process_crash",
            "detail":   crash["line"][:150],
        })

    print(f"\n[+] Session complete. {len(result['findings'])} findings.")
    return result


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== android_surface.py self-test ===\n")

    print("[1] Device check:")
    dev = check_device()
    print(f"    Connected: {dev['connected']}")
    if dev["connected"]:
        for k, v in dev["info"].items():
            print(f"    {k}: {v}")

    print("\n[2] Frida hooks generated:")
    hooks = frida_hooks("all")
    for name, script in hooks.items():
        if name != "all":
            print(f"    {name}: {len(script)} chars")

    print("\n[3] MMS PDU generation:")
    result = fuzz_mms()
    print(f"    Generated: {result['payloads_generated']} PDUs")

    print("\nDone.")
