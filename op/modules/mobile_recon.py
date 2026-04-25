"""
mobile_recon.py — Android/iOS Mobile App Recon Module
WiZZA Pentest Toolkit

Techniques:
  1. APK/AAB static analysis — extract manifest, strings, endpoints
  2. Hardcoded secret detection — API keys, tokens, passwords in code
  3. Firebase config extraction — project ID, DB URL, API key
  4. Network security config audit — cleartext, pinning, custom CAs
  5. Exported component enumeration — activities, services, receivers
  6. Deep link extraction — custom URI schemes
  7. Frida hook generation — auto-gen scripts for SSL unpin + intercept
  8. IPA static analysis — iOS app binary + plist inspection

Usage:
  from mobile_recon import analyze_apk, analyze_aab, find_secrets, gen_frida_script
  from mobile_recon import full_mobile_recon
"""

import os
import re
import json
import struct
import zipfile
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

# ── Secret patterns ───────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    "Google API Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase API Key":       r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth":           r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "AWS Access Key":         r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":         r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "Stripe Secret Key":      r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Publishable Key": r'pk_live_[0-9a-zA-Z]{24,}',
    "Supabase Key":           r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    "Firebase DB URL":        r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Firebase Storage":       r'gs://[a-z0-9\-]+\.appspot\.com',
    "JWT Token":              r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}',
    "Generic Password":       r'(?i)password["\s]*[:=]["\s]*[^\s"]{6,}',
    "Generic Secret":         r'(?i)secret["\s]*[:=]["\s]*[^\s"]{8,}',
    "Generic Token":          r'(?i)token["\s]*[:=]["\s]*[A-Za-z0-9\-_]{16,}',
    "Private Key Header":     r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "Twilio API Key":         r'SK[0-9a-fA-F]{32}',
    "Sendgrid Key":           r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    "Mapbox Token":           r'pk\.eyJ1Ijoi[A-Za-z0-9\-_]+',
    "PayPal Client ID":       r'(?i)paypal.{0,10}client.{0,10}[\'"][A-Za-z0-9]{20,}[\'"]',
    "Hardcoded URL":          r'https?://(?:localhost|127\.0\.0\.1|192\.168\.|10\.|172\.[123]\d\.)[^\s"\']+',
}

# ── APK Analysis ──────────────────────────────────────────────────────────────

def _extract_zip(archive_path: str, extract_dir: str, filter_fn=None) -> list:
    """Extract archive files matching filter."""
    extracted = []
    try:
        with zipfile.ZipFile(archive_path, 'r') as z:
            for name in z.namelist():
                if filter_fn is None or filter_fn(name):
                    try:
                        z.extract(name, extract_dir)
                        extracted.append(os.path.join(extract_dir, name))
                    except Exception:
                        pass
    except Exception as e:
        pass
    return extracted


def _scan_strings(data: bytes, min_len: int = 8) -> list:
    """Extract printable strings from binary data."""
    strings = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings


def find_secrets(text: str, source: str = "unknown") -> list:
    """Scan text for hardcoded secrets using pattern matching."""
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            value = match.group(0)
            # Skip obvious false positives
            if len(set(value)) < 4:
                continue
            findings.append({
                "type": name,
                "value": value[:80] + ("..." if len(value) > 80 else ""),
                "source": source,
                "offset": match.start(),
            })
    return findings


def analyze_apk(apk_path: str) -> dict:
    """
    Static analysis of an APK file.
    Extracts: manifest, permissions, exports, Firebase config, secrets.
    """
    result = {
        "file": apk_path,
        "type": "APK",
        "timestamp": datetime.now().isoformat(),
        "package": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "exported_activities": [],
        "exported_services": [],
        "exported_receivers": [],
        "deep_links": [],
        "firebase_config": {},
        "network_security": {},
        "endpoints": [],
        "secrets": [],
        "interesting_files": [],
        "errors": [],
    }

    if not os.path.exists(apk_path):
        result["errors"].append(f"File not found: {apk_path}")
        return result

    tmpdir = tempfile.mkdtemp(prefix="wizza_apk_")

    try:
        # ── Decompile with apktool (if available) ──
        apktool_out = os.path.join(tmpdir, "apktool_out")
        apktool_result = subprocess.run(
            ["apktool", "d", "-f", "-o", apktool_out, apk_path],
            capture_output=True, text=True, timeout=120
        )
        use_apktool = apktool_result.returncode == 0

        # ── Fallback: raw zip extraction ──
        zip_out = os.path.join(tmpdir, "zip_out")
        os.makedirs(zip_out, exist_ok=True)
        _extract_zip(apk_path, zip_out)

        # ── Parse AndroidManifest.xml ──
        manifest_path = None
        if use_apktool:
            manifest_path = os.path.join(apktool_out, "AndroidManifest.xml")

        if manifest_path and os.path.exists(manifest_path):
            with open(manifest_path, "r", errors="replace") as f:
                manifest_text = f.read()

            # Package name
            pkg = re.search(r'package=["\']([^"\']+)["\']', manifest_text)
            if pkg:
                result["package"] = pkg.group(1)

            # SDK versions
            min_sdk = re.search(r'minSdkVersion=["\'](\d+)["\']', manifest_text)
            if min_sdk:
                result["min_sdk"] = int(min_sdk.group(1))

            target_sdk = re.search(r'targetSdkVersion=["\'](\d+)["\']', manifest_text)
            if target_sdk:
                result["target_sdk"] = int(target_sdk.group(1))

            # Permissions
            result["permissions"] = re.findall(
                r'uses-permission[^>]+name=["\']([^"\']+)["\']', manifest_text
            )

            # Exported components
            for activity in re.finditer(
                r'<activity[^>]+name=["\']([^"\']+)["\'][^>]*exported=["\']true["\']',
                manifest_text
            ):
                result["exported_activities"].append(activity.group(1))

            for service in re.finditer(
                r'<service[^>]+name=["\']([^"\']+)["\'][^>]*exported=["\']true["\']',
                manifest_text
            ):
                result["exported_services"].append(service.group(1))

            # Deep links
            for scheme in re.finditer(r'<data[^>]+scheme=["\']([^"\']+)["\']', manifest_text):
                result["deep_links"].append(scheme.group(1))

        # ── Firebase config (google-services.json) ──
        gs_path = None
        for root, dirs, files in os.walk(zip_out if not use_apktool else apktool_out):
            for fname in files:
                if fname == "google-services.json":
                    gs_path = os.path.join(root, fname)
                    break

        if gs_path and os.path.exists(gs_path):
            try:
                with open(gs_path) as f:
                    gs = json.load(f)
                result["firebase_config"] = {
                    "project_id": gs.get("project_info", {}).get("project_id"),
                    "project_number": gs.get("project_info", {}).get("project_number"),
                    "firebase_url": gs.get("project_info", {}).get("firebase_url"),
                    "storage_bucket": gs.get("project_info", {}).get("storage_bucket"),
                    "api_key": gs.get("client", [{}])[0].get("api_key", [{}])[0].get("current_key"),
                }
                result["interesting_files"].append(gs_path)
            except Exception:
                pass

        # ── Network security config ──
        nsc_paths = []
        for root, dirs, files in os.walk(zip_out if not use_apktool else apktool_out):
            for fname in files:
                if "network_security_config" in fname.lower() and fname.endswith(".xml"):
                    nsc_paths.append(os.path.join(root, fname))

        for nsc_path in nsc_paths:
            try:
                with open(nsc_path, "r", errors="replace") as f:
                    nsc_text = f.read()
                result["network_security"] = {
                    "allows_cleartext": "cleartextTrafficPermitted=\"true\"" in nsc_text,
                    "certificate_pinning": "<pin-set" in nsc_text,
                    "user_trust_anchors": "user" in nsc_text and "certificates" in nsc_text,
                    "raw": nsc_text[:500],
                }
            except Exception:
                pass

        # ── Scan all text files for secrets and endpoints ──
        scan_dirs = [apktool_out if use_apktool else zip_out]
        for scan_dir in scan_dirs:
            for root, dirs, files in os.walk(scan_dir):
                # Skip large dirs
                dirs[:] = [d for d in dirs if d not in ["META-INF", ".git"]]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in (".smali", ".xml", ".json", ".properties",
                               ".txt", ".js", ".ts", ".kt", ".java", ".py"):
                        try:
                            with open(fpath, "r", errors="replace") as f:
                                content = f.read()
                            rel = os.path.relpath(fpath, scan_dir)

                            # Secret scan
                            secrets = find_secrets(content, source=rel)
                            result["secrets"].extend(secrets)

                            # API endpoint extraction
                            for ep in re.findall(
                                r'https?://[A-Za-z0-9\-\.]+(?:\.[a-z]{2,})+[/A-Za-z0-9\-_\.?=&%]*',
                                content
                            ):
                                if ep not in result["endpoints"] and len(ep) < 200:
                                    result["endpoints"].append(ep)

                        except Exception:
                            pass
                    elif ext in (".so", ".dex"):
                        try:
                            with open(fpath, "rb") as f:
                                data = f.read()
                            strings = _scan_strings(data)
                            text = "\n".join(strings)
                            rel = os.path.relpath(fpath, scan_dir)
                            secrets = find_secrets(text, source=rel)
                            result["secrets"].extend(secrets)
                        except Exception:
                            pass

        # Deduplicate endpoints
        result["endpoints"] = sorted(set(result["endpoints"]))[:100]

        # Deduplicate secrets by value
        seen_vals = set()
        unique_secrets = []
        for s in result["secrets"]:
            if s["value"] not in seen_vals:
                seen_vals.add(s["value"])
                unique_secrets.append(s)
        result["secrets"] = unique_secrets

    except Exception as e:
        result["errors"].append(str(e))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


def analyze_aab(aab_path: str) -> dict:
    """
    Static analysis of an Android App Bundle (AAB).
    AABs are zip files containing split APKs and a BundleConfig.
    """
    result = {
        "file": aab_path,
        "type": "AAB",
        "timestamp": datetime.now().isoformat(),
        "bundle_config": {},
        "modules": [],
        "secrets": [],
        "endpoints": [],
        "firebase_config": {},
        "errors": [],
    }

    if not os.path.exists(aab_path):
        result["errors"].append(f"File not found: {aab_path}")
        return result

    tmpdir = tempfile.mkdtemp(prefix="wizza_aab_")

    try:
        # AABs are zips containing base/, feature/ modules
        with zipfile.ZipFile(aab_path, 'r') as z:
            z.extractall(tmpdir)

        # List modules
        result["modules"] = [
            d for d in os.listdir(tmpdir)
            if os.path.isdir(os.path.join(tmpdir, d))
        ]

        # Find BundleConfig.pb
        bc_path = os.path.join(tmpdir, "BundleConfig.pb")
        if os.path.exists(bc_path):
            with open(bc_path, "rb") as f:
                data = f.read()
            strings = _scan_strings(data, min_len=4)
            result["bundle_config"]["strings"] = strings[:50]

        # Find google-services.json in base module
        for root, dirs, files in os.walk(tmpdir):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                if fname == "google-services.json":
                    try:
                        with open(fpath) as f:
                            gs = json.load(f)
                        result["firebase_config"] = {
                            "project_id":     gs.get("project_info", {}).get("project_id"),
                            "firebase_url":   gs.get("project_info", {}).get("firebase_url"),
                            "storage_bucket": gs.get("project_info", {}).get("storage_bucket"),
                            "api_key":        gs.get("client", [{}])[0].get("api_key", [{}])[0].get("current_key"),
                        }
                    except Exception:
                        pass

                # Scan text files
                if ext in (".xml", ".json", ".properties", ".txt", ".js", ".kt", ".java"):
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            content = f.read()
                        rel = os.path.relpath(fpath, tmpdir)
                        secrets = find_secrets(content, source=rel)
                        result["secrets"].extend(secrets)
                        for ep in re.findall(
                            r'https?://[A-Za-z0-9\-\.]+(?:\.[a-z]{2,})+[/A-Za-z0-9\-_\.?=&%]*',
                            content
                        ):
                            if ep not in result["endpoints"]:
                                result["endpoints"].append(ep)
                    except Exception:
                        pass

                # Scan DEX files for strings
                elif ext == ".dex":
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read()
                        strings = _scan_strings(data)
                        text = "\n".join(strings)
                        rel = os.path.relpath(fpath, tmpdir)
                        secrets = find_secrets(text, source=rel)
                        result["secrets"].extend(secrets)
                        for ep in re.findall(
                            r'https?://[A-Za-z0-9\-\.]+(?:\.[a-z]{2,})+[/A-Za-z0-9\-_\.?=&%]*',
                            text
                        ):
                            if ep not in result["endpoints"]:
                                result["endpoints"].append(ep)
                    except Exception:
                        pass

        # Deduplicate
        result["endpoints"] = sorted(set(result["endpoints"]))[:100]
        seen_vals = set()
        result["secrets"] = [
            s for s in result["secrets"]
            if s["value"] not in seen_vals and not seen_vals.add(s["value"])
        ]

    except Exception as e:
        result["errors"].append(str(e))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


# ── Frida Script Generation ───────────────────────────────────────────────────

def gen_frida_script(package: str = None, mode: str = "ssl_unpin") -> str:
    """
    Generate a Frida hook script for mobile app instrumentation.

    Modes:
      ssl_unpin    — disable SSL certificate pinning
      intercept    — log all HTTP/HTTPS requests and responses
      auth_bypass  — hook auth methods to always return success
      full         — all of the above
    """
    scripts = {}

    scripts["ssl_unpin"] = f"""
/* Frida SSL Unpinning Script — WiZZA Mobile Recon
 * Target: {package or 'any Android app'}
 * Usage: frida -U -f {package or 'com.target.app'} -l ssl_unpin.js --no-pause
 */

Java.perform(function() {{
    console.log('[WiZZA] SSL unpinning started');

    // OkHttp3 CertificatePinner
    try {{
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certs) {{
            console.log('[*] OkHttp3 CertificatePinner.check bypassed for: ' + hostname);
        }};
        console.log('[+] OkHttp3 pinning bypassed');
    }} catch(e) {{ console.log('[-] OkHttp3 not found'); }}

    // TrustManagerImpl
    try {{
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {{
            console.log('[*] TrustManagerImpl.verifyChain bypassed for: ' + host);
            return untrustedChain;
        }};
        console.log('[+] TrustManagerImpl bypassed');
    }} catch(e) {{ console.log('[-] TrustManagerImpl not found'); }}

    // X509TrustManager
    try {{
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({{
            name: 'wizza.TrustManager',
            implements: [X509TrustManager],
            methods: {{
                checkClientTrusted: function(chain, authType) {{}},
                checkServerTrusted: function(chain, authType) {{
                    console.log('[*] X509TrustManager.checkServerTrusted bypassed');
                }},
                getAcceptedIssuers: function() {{ return []; }},
            }}
        }});
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.getDefault.implementation = function() {{ return ctx; }};
        console.log('[+] X509TrustManager bypassed');
    }} catch(e) {{ console.log('[-] X509TrustManager hook failed: ' + e); }}

    // WebViewClient (for WebView SSL errors)
    try {{
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overload(
            'android.webkit.WebView',
            'android.webkit.SslErrorHandler',
            'android.net.http.SslError'
        ).implementation = function(webView, handler, error) {{
            console.log('[*] WebViewClient SSL error bypassed');
            handler.proceed();
        }};
        console.log('[+] WebViewClient SSL bypass active');
    }} catch(e) {{ console.log('[-] WebViewClient hook failed'); }}

    // Firebase (if present)
    try {{
        var FirebaseApp = Java.use('com.google.firebase.FirebaseApp');
        console.log('[*] Firebase detected: ' + FirebaseApp.getApps().size() + ' app(s)');
    }} catch(e) {{}}

    console.log('[WiZZA] SSL unpinning complete');
}});
"""

    scripts["intercept"] = f"""
/* Frida HTTP Intercept Script — WiZZA Mobile Recon
 * Intercepts OkHttp3 + Volley + HttpURLConnection requests
 */

Java.perform(function() {{
    console.log('[WiZZA] HTTP intercept started');

    // OkHttp3 request/response logging
    try {{
        var Builder = Java.use('okhttp3.Request$Builder');
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Chain = Java.use('okhttp3.Interceptor$Chain');

        OkHttpClient.newCall.implementation = function(request) {{
            var url = request.url().toString();
            var method = request.method();
            var headers = request.headers().toString();
            console.log('[REQ] ' + method + ' ' + url);
            console.log('      Headers: ' + headers.replace(/\\n/g, ' | '));
            var body = request.body();
            if (body !== null) {{
                // Log body type
                console.log('      Body type: ' + body.contentType());
            }}
            return this.newCall(request);
        }};
        console.log('[+] OkHttp3 intercept active');
    }} catch(e) {{ console.log('[-] OkHttp3 intercept failed: ' + e); }}

    // HttpURLConnection
    try {{
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getResponseCode.implementation = function() {{
            var code = this.getResponseCode();
            var url = this.getURL().toString();
            console.log('[RES] ' + code + ' ' + url);
            return code;
        }};
        console.log('[+] HttpURLConnection intercept active');
    }} catch(e) {{ console.log('[-] HttpURLConnection intercept failed'); }}

    console.log('[WiZZA] HTTP intercept ready');
}});
"""

    scripts["auth_bypass"] = f"""
/* Frida Auth Bypass Script — WiZZA Mobile Recon
 * Hooks common auth patterns to return success
 */

Java.perform(function() {{
    console.log('[WiZZA] Auth bypass hooks starting');

    // SharedPreferences boolean reads (e.g. "is_logged_in", "is_premium")
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    // Hook implementations via class loaders
    Java.enumerateLoadedClasses({{
        onMatch: function(className) {{
            if (className.indexOf('SharedPreferences') >= 0 ||
                className.indexOf('PreferenceImpl') >= 0) {{
                try {{
                    var cls = Java.use(className);
                    if (cls.getBoolean) {{
                        cls.getBoolean.overload('java.lang.String', 'boolean').implementation = function(key, def) {{
                            var val = this.getBoolean(key, def);
                            if (key.toLowerCase().indexOf('premium') >= 0 ||
                                key.toLowerCase().indexOf('subscri') >= 0 ||
                                key.toLowerCase().indexOf('pro') >= 0) {{
                                console.log('[*] Returning true for SharedPref: ' + key);
                                return true;
                            }}
                            return val;
                        }};
                    }}
                }} catch(e) {{}}
            }}
        }},
        onComplete: function() {{}}
    }});

    console.log('[WiZZA] Auth bypass hooks installed');
}});
"""

    scripts["full"] = scripts["ssl_unpin"] + "\n" + scripts["intercept"] + "\n" + scripts["auth_bypass"]

    return scripts.get(mode, scripts["ssl_unpin"])


# ── IPA Analysis (iOS) ────────────────────────────────────────────────────────

def analyze_ipa(ipa_path: str) -> dict:
    """
    Static analysis of an iOS IPA file.
    Extracts Info.plist, ATS config, URL schemes, and secrets.
    """
    result = {
        "file": ipa_path,
        "type": "IPA",
        "timestamp": datetime.now().isoformat(),
        "bundle_id": None,
        "app_name": None,
        "min_ios": None,
        "url_schemes": [],
        "ats_config": {},
        "permissions": [],
        "secrets": [],
        "endpoints": [],
        "errors": [],
    }

    if not os.path.exists(ipa_path):
        result["errors"].append(f"File not found: {ipa_path}")
        return result

    tmpdir = tempfile.mkdtemp(prefix="wizza_ipa_")
    try:
        with zipfile.ZipFile(ipa_path, 'r') as z:
            z.extractall(tmpdir)

        # Find Info.plist
        plist_paths = []
        for root, dirs, files in os.walk(tmpdir):
            for fname in files:
                if fname == "Info.plist":
                    plist_paths.append(os.path.join(root, fname))

        for plist_path in plist_paths[:1]:
            try:
                # Try plutil if available
                out = subprocess.check_output(
                    ["plutil", "-convert", "json", "-o", "-", plist_path],
                    text=True, timeout=10
                )
                plist = json.loads(out)
            except (FileNotFoundError, subprocess.CalledProcessError):
                # Parse binary plist manually (basic)
                try:
                    with open(plist_path, "rb") as f:
                        data = f.read()
                    plist = {"_raw_strings": _scan_strings(data)}
                except Exception:
                    plist = {}

            result["bundle_id"] = plist.get("CFBundleIdentifier")
            result["app_name"]  = plist.get("CFBundleDisplayName") or plist.get("CFBundleName")
            result["min_ios"]   = plist.get("MinimumOSVersion")

            # URL schemes
            for item in plist.get("CFBundleURLTypes", []):
                for scheme in item.get("CFBundleURLSchemes", []):
                    result["url_schemes"].append(scheme)

            # ATS (App Transport Security)
            ats = plist.get("NSAppTransportSecurity", {})
            result["ats_config"] = {
                "allows_arbitrary_loads": ats.get("NSAllowsArbitraryLoads", False),
                "allows_arbitrary_loads_for_media": ats.get("NSAllowsArbitraryLoadsForMedia", False),
                "exception_domains": list(ats.get("NSExceptionDomains", {}).keys()),
            }

            # Permissions
            perm_keys = [k for k in plist.keys() if k.startswith("NS") and "UsageDescription" in k]
            result["permissions"] = perm_keys

        # Scan binary for secrets
        for root, dirs, files in os.walk(tmpdir):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                if ext in (".plist", ".json", ".strings", ".txt"):
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            content = f.read()
                        rel = os.path.relpath(fpath, tmpdir)
                        result["secrets"].extend(find_secrets(content, source=rel))
                        for ep in re.findall(
                            r'https?://[A-Za-z0-9\-\.]+(?:\.[a-z]{2,})+[/A-Za-z0-9\-_\.?=&%]*',
                            content
                        ):
                            if ep not in result["endpoints"]:
                                result["endpoints"].append(ep)
                    except Exception:
                        pass
                elif ext in ("", ".dylib", ".framework"):
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read()
                        strings = _scan_strings(data)
                        text = "\n".join(strings)
                        rel = os.path.relpath(fpath, tmpdir)
                        result["secrets"].extend(find_secrets(text, source=rel))
                    except Exception:
                        pass

        # Deduplicate
        result["endpoints"] = sorted(set(result["endpoints"]))[:100]
        seen_vals = set()
        result["secrets"] = [
            s for s in result["secrets"]
            if s["value"] not in seen_vals and not seen_vals.add(s["value"])
        ]

    except Exception as e:
        result["errors"].append(str(e))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


# ── Full Mobile Recon ─────────────────────────────────────────────────────────

def full_mobile_recon(file_path: str, frida_mode: str = "ssl_unpin") -> dict:
    """
    Auto-detect file type and run full static recon.
    Returns analysis + generated Frida script.
    """
    ext = os.path.splitext(file_path)[1].lower()
    print(f"[*] Mobile recon: {file_path}")

    if ext == ".apk":
        print("  [1/2] APK static analysis...")
        analysis = analyze_apk(file_path)
    elif ext == ".aab":
        print("  [1/2] AAB static analysis...")
        analysis = analyze_aab(file_path)
    elif ext == ".ipa":
        print("  [1/2] IPA static analysis...")
        analysis = analyze_ipa(file_path)
    else:
        return {"error": f"Unknown extension: {ext}. Supported: .apk, .aab, .ipa"}

    print(f"  [2/2] Generating Frida script (mode={frida_mode})...")
    pkg = analysis.get("package") or analysis.get("bundle_id")
    frida_script = gen_frida_script(pkg, frida_mode)

    out_dir = "/tmp/wizza_mobile"
    os.makedirs(out_dir, exist_ok=True)
    frida_path = os.path.join(out_dir, f"frida_{frida_mode}.js")
    with open(frida_path, "w") as f:
        f.write(frida_script)

    analysis["frida_script"] = frida_path

    # Summary
    n_secrets  = len(analysis.get("secrets", []))
    n_endpoints = len(analysis.get("endpoints", []))
    print(f"\n  Results: {n_secrets} secrets found, {n_endpoints} endpoints found")
    if analysis.get("firebase_config", {}).get("project_id"):
        print(f"  Firebase: {analysis['firebase_config']['project_id']}")

    return analysis


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    print("=== mobile_recon.py self-test ===\n")

    # Test secret detection
    print("[1] Secret pattern detection:")
    test_text = """
    val API_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuvwx"
    val FB_URL = "https://myapp-default-rtdb.firebaseio.com"
    val TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123"
    val DB_PASS = "password = secret123pass"
    val AWS = "AKIAIOSFODNN7EXAMPLE"
    """
    findings = find_secrets(test_text, "test_string")
    for f in findings:
        print(f"    [{f['type']}] {f['value'][:50]}")

    print("\n[2] Frida script generation:")
    script = gen_frida_script("com.julazone.app", "ssl_unpin")
    print(f"    Generated {len(script)} chars of Frida JS")

    # Test on lumo-app AAB if present
    aab_path = "/home/heilige/lumo-app/julazone-v1.1.0-release.aab"
    if os.path.exists(aab_path):
        print(f"\n[3] AAB analysis: {aab_path}")
        result = analyze_aab(aab_path)
        print(f"    Modules: {result['modules']}")
        print(f"    Firebase: {result['firebase_config']}")
        print(f"    Secrets: {len(result['secrets'])}")
        print(f"    Endpoints: {len(result['endpoints'])}")
        for s in result["secrets"][:5]:
            print(f"      [{s['type']}] {s['value'][:60]}")
    else:
        print("\n[3] No AAB found for live test")

    print("\nDone.")
