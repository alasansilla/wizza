"""
otp_tester.py — OTP / 2FA Security Testing Module
WiZZA Pentest Toolkit

Tests your own 2FA implementation for weaknesses:
  1. Rate limit testing   — how many attempts before lockout?
  2. OTP length brute     — test if short/predictable OTPs are accepted
  3. Backup code probe    — check backup code endpoint security
  4. OTP reuse test       — can the same OTP be used twice?
  5. Time window test     — how far outside the window are OTPs accepted?
  6. Response enumeration — does error message reveal validity?
  7. TOTP secret extract  — check if secret is exposed in QR/API
  8. SMS OTP analysis     — analyze SMS delivery patterns + SIM swap risk

Usage:
  from otp_tester import test_rate_limit, test_otp_reuse, test_time_window
  from otp_tester import full_2fa_audit, gen_totp_codes
"""

import time
import hmac
import struct
import hashlib
import base64
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ── TOTP Implementation ───────────────────────────────────────────────────────

def gen_totp(secret: str, t: int = None, digits: int = 6, period: int = 30) -> str:
    """
    Generate a TOTP code (RFC 6238) for a given base32 secret.
    If t is None, uses current time.
    """
    if t is None:
        t = int(time.time())

    # Normalize secret
    secret = secret.upper().replace(" ", "").replace("-", "")
    # Pad to multiple of 8
    padding = (8 - len(secret) % 8) % 8
    secret += "=" * padding

    try:
        key = base64.b32decode(secret)
    except Exception:
        # Try treating as hex
        try:
            key = bytes.fromhex(secret.lower()[:len(secret) - padding])
        except Exception:
            return "000000"

    counter = t // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def gen_totp_window(secret: str, window: int = 2, digits: int = 6, period: int = 30) -> list:
    """Generate TOTP codes for a time window (past/current/future)."""
    t = int(time.time())
    codes = []
    for i in range(-window, window + 1):
        ts = t + (i * period)
        code = gen_totp(secret, ts, digits, period)
        codes.append({
            "offset":    i,
            "timestamp": ts,
            "code":      code,
            "label":     "current" if i == 0 else (f"+{i}" if i > 0 else str(i)),
        })
    return codes


# ── HTTP Helper ───────────────────────────────────────────────────────────────

def _post(url: str, data: dict, headers: dict = None, timeout: int = 8,
          cookie: str = None) -> tuple:
    """POST request, returns (status, body_text, response_headers)."""
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0 (WiZZA OTP Tester)")
    if cookie:
        req.add_header("Cookie", cookie)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(4096).decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(2048).decode(errors="replace"), dict(e.headers)
        except Exception:
            return e.code, "", {}
    except Exception as e:
        return 0, str(e), {}


def _get(url: str, headers: dict = None, timeout: int = 8, cookie: str = None) -> tuple:
    """GET request, returns (status, body_text, response_headers)."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (WiZZA OTP Tester)")
    if cookie:
        req.add_header("Cookie", cookie)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(4096).decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(2048).decode(errors="replace"), dict(e.headers)
        except Exception:
            return e.code, "", {}
    except Exception as e:
        return 0, str(e), {}


# ── 1. Rate Limit Testing ─────────────────────────────────────────────────────

def test_rate_limit(endpoint: str, otp_field: str = "otp",
                    extra_fields: dict = None, max_attempts: int = 20,
                    delay: float = 0.5, cookie: str = None) -> dict:
    """
    Test OTP endpoint for rate limiting.
    Sends wrong OTP codes and measures when/if lockout occurs.
    """
    result = {
        "endpoint":     endpoint,
        "max_tested":   max_attempts,
        "delay_s":      delay,
        "responses":    [],
        "lockout_at":   None,
        "rate_limited": False,
        "verdict":      None,
    }

    for i in range(1, max_attempts + 1):
        # Generate wrong OTP (sequential, clearly invalid)
        wrong_otp = str(i).zfill(6)
        fields = {otp_field: wrong_otp}
        if extra_fields:
            fields.update(extra_fields)

        status, body, hdrs = _post(endpoint, fields, cookie=cookie)

        entry = {
            "attempt":  i,
            "otp":      wrong_otp,
            "status":   status,
            "body_len": len(body),
            "body":     body[:100],
        }
        result["responses"].append(entry)

        # Detect rate limiting
        if status == 429:
            result["rate_limited"] = True
            result["lockout_at"]   = i
            entry["note"] = "RATE LIMITED"
            break

        if any(kw in body.lower() for kw in
               ["too many", "rate limit", "locked", "blocked", "try again later"]):
            result["rate_limited"] = True
            result["lockout_at"]   = i
            entry["note"] = "SOFT LOCKOUT DETECTED"
            break

        if i < max_attempts:
            time.sleep(delay)

    if result["rate_limited"]:
        result["verdict"] = f"Rate limited after {result['lockout_at']} attempts"
    else:
        result["verdict"] = f"NO rate limit detected after {max_attempts} attempts — VULNERABLE"

    return result


# ── 2. OTP Reuse Test ─────────────────────────────────────────────────────────

def test_otp_reuse(endpoint: str, valid_otp: str, otp_field: str = "otp",
                   extra_fields: dict = None, cookie: str = None) -> dict:
    """
    Test if a valid OTP can be used more than once (replay attack).
    Requires a known valid OTP to test with.
    """
    result = {
        "endpoint":    endpoint,
        "otp_tested":  valid_otp,
        "attempts":    [],
        "reuse_vuln":  False,
        "verdict":     None,
    }

    fields = {otp_field: valid_otp}
    if extra_fields:
        fields.update(extra_fields)

    for attempt in range(1, 4):
        status, body, hdrs = _post(endpoint, fields, cookie=cookie)
        entry = {
            "attempt": attempt,
            "status":  status,
            "body":    body[:150],
            "success": status == 200 and not any(
                kw in body.lower() for kw in ["invalid", "expired", "wrong", "error"]
            ),
        }
        result["attempts"].append(entry)
        time.sleep(0.5)

    successes = sum(1 for a in result["attempts"] if a["success"])
    if successes > 1:
        result["reuse_vuln"] = True
        result["verdict"] = f"VULNERABLE — OTP accepted {successes}/3 times (replay attack possible)"
    elif successes == 1:
        result["verdict"] = "OTP only accepted once (correct behavior)"
    else:
        result["verdict"] = "OTP not accepted — may already be expired or invalid"

    return result


# ── 3. OTP Length / Brute Force Viability ────────────────────────────────────

def test_otp_length(endpoint: str, otp_field: str = "otp",
                    extra_fields: dict = None, cookie: str = None) -> dict:
    """
    Test if short OTPs or out-of-range values are accepted.
    Checks: 4-digit codes, all-zeros, all-nines, out-of-range.
    """
    result = {
        "endpoint": endpoint,
        "tests":    [],
        "findings": [],
    }

    test_cases = [
        ("4-digit OTP",      "1234"),
        ("4-digit zeros",    "0000"),
        ("5-digit",          "12345"),
        ("7-digit",          "1234567"),
        ("all zeros 6",      "000000"),
        ("all nines 6",      "999999"),
        ("negative",         "-00001"),
        ("float",            "123.45"),
        ("null byte",        "000\x00000"),
        ("overflow",         "9" * 20),
        ("empty",            ""),
        ("whitespace",       "      "),
        ("sql inject",       "' OR '1'='1"),
    ]

    for name, otp_val in test_cases:
        fields = {otp_field: otp_val}
        if extra_fields:
            fields.update(extra_fields)

        status, body, _ = _post(endpoint, fields, cookie=cookie, timeout=5)
        accepted = status == 200 and not any(
            kw in body.lower() for kw in ["invalid", "wrong", "error", "expired"]
        )

        entry = {
            "test":     name,
            "value":    repr(otp_val),
            "status":   status,
            "accepted": accepted,
        }
        result["tests"].append(entry)

        if accepted:
            result["findings"].append(f"ACCEPTED: {name} ({repr(otp_val)})")

        time.sleep(0.2)

    return result


# ── 4. Time Window Analysis ────────────────────────────────────────────────────

def test_time_window(endpoint: str, totp_secret: str, otp_field: str = "otp",
                     extra_fields: dict = None, cookie: str = None,
                     max_window: int = 10) -> dict:
    """
    Test how wide the TOTP acceptance window is.
    RFC 6238 allows ±1 step (30s). Wider windows are a vulnerability.
    """
    result = {
        "endpoint":       endpoint,
        "period_tested":  30,
        "accepted_steps": [],
        "max_past":       0,
        "max_future":     0,
        "verdict":        None,
    }

    t = int(time.time())

    for offset in range(-max_window, max_window + 1):
        ts = t + (offset * 30)
        code = gen_totp(totp_secret, ts)
        fields = {otp_field: code}
        if extra_fields:
            fields.update(extra_fields)

        status, body, _ = _post(endpoint, fields, cookie=cookie, timeout=5)
        accepted = status == 200 and not any(
            kw in body.lower() for kw in ["invalid", "wrong", "error", "expired"]
        )

        if accepted:
            result["accepted_steps"].append(offset)
            if offset < 0:
                result["max_past"]   = max(result["max_past"],   abs(offset))
            elif offset > 0:
                result["max_future"] = max(result["max_future"], offset)

        time.sleep(0.3)

    if not result["accepted_steps"]:
        result["verdict"] = "No valid TOTP accepted — check secret or endpoint"
    elif result["max_past"] > 1 or result["max_future"] > 1:
        total_window = (result["max_past"] + result["max_future"]) * 30
        result["verdict"] = (
            f"WIDE WINDOW: accepts ±{max(result['max_past'], result['max_future'])} steps "
            f"(±{total_window}s). RFC allows ±30s. Brute-force window enlarged."
        )
    else:
        result["verdict"] = f"Window within RFC spec (±1 step = ±30s)"

    return result


# ── 5. Backup Code Testing ────────────────────────────────────────────────────

def test_backup_codes(base_url: str, backup_endpoint: str = "/api/auth/backup",
                      cookie: str = None) -> dict:
    """
    Test backup code endpoint for:
    - Unauthenticated access
    - Predictable codes (sequential, date-based)
    - Unlimited attempts
    - Code format validation bypass
    """
    result = {
        "endpoint": base_url + backup_endpoint,
        "tests":    [],
        "findings": [],
    }

    # Test 1: Unauthenticated access
    status, body, _ = _get(base_url + backup_endpoint)
    result["tests"].append({
        "test":   "unauthenticated_GET",
        "status": status,
        "note":   "Should be 401/403" if status not in (200, 201) else "WARNING: accessible unauthenticated"
    })
    if status == 200:
        result["findings"].append("Backup code endpoint accessible without auth")

    # Test 2: Try common backup code patterns
    common_codes = [
        "00000000", "12345678", "87654321",
        "11111111", "99999999", "00000001",
    ]
    backup_field = "backup_code"
    for code in common_codes:
        s, b, _ = _post(base_url + backup_endpoint,
                        {backup_field: code}, cookie=cookie, timeout=5)
        if s == 200 and "success" in b.lower():
            result["findings"].append(f"Common backup code accepted: {code}")
        result["tests"].append({"test": f"common_code_{code}", "status": s})
        time.sleep(0.2)

    return result


# ── 6. SMS OTP Analysis ────────────────────────────────────────────────────────

def analyze_sms_otp(endpoint: str, phone: str, otp_field: str = "otp",
                    phone_field: str = "phone", cookie: str = None) -> dict:
    """
    Analyze SMS OTP delivery and test for:
    - OTP length / entropy
    - Resend rate limit
    - Phone number enumeration
    - International number bypass (e.g. send to attacker's number)
    """
    result = {
        "endpoint":   endpoint,
        "phone":      phone,
        "tests":      [],
        "findings":   [],
    }

    # Test 1: Resend rate limit
    print("  Testing SMS resend rate limit...")
    resend_results = []
    for i in range(5):
        s, b, _ = _post(endpoint, {phone_field: phone}, timeout=8)
        resend_results.append({"attempt": i+1, "status": s, "body": b[:80]})
        if s == 429 or "rate" in b.lower() or "limit" in b.lower():
            result["findings"].append(f"Rate limited after {i+1} resend(s)")
            break
        time.sleep(1)

    if not any(r["status"] == 429 for r in resend_results):
        result["findings"].append("No resend rate limit — OTP bombing possible")

    result["tests"].append({
        "test":    "resend_rate_limit",
        "results": resend_results,
    })

    # Test 2: International number substitution
    # (Does the endpoint accept a different number than the authenticated user?)
    intl_numbers = ["+1234567890", "+447700900123", "+220123456789"]
    for num in intl_numbers:
        s, b, _ = _post(endpoint, {phone_field: num}, cookie=cookie, timeout=5)
        if s == 200 and "sent" in b.lower():
            result["findings"].append(
                f"OTP sent to arbitrary number {num} — possible account takeover if "
                "OTP destination is not tied to authenticated session"
            )
        result["tests"].append({
            "test":   f"intl_number_{num}",
            "status": s,
            "body":   b[:80],
        })
        time.sleep(0.5)

    return result


# ── 7. TOTP Secret Exposure Check ────────────────────────────────────────────

def check_totp_secret_exposure(base_url: str, cookie: str = None) -> dict:
    """
    Check if the TOTP secret is exposed in API responses.
    Some apps return the raw secret instead of just a QR code URL.
    """
    result = {
        "endpoints_checked": [],
        "secrets_found":     [],
        "qr_urls":           [],
    }

    totp_endpoints = [
        "/api/auth/totp/setup",
        "/api/2fa/setup",
        "/api/user/2fa",
        "/api/auth/2fa/generate",
        "/api/settings/2fa",
        "/api/profile/2fa",
    ]

    for ep in totp_endpoints:
        s, b, _ = _get(base_url + ep, cookie=cookie, timeout=5)
        result["endpoints_checked"].append({"endpoint": ep, "status": s})

        if s in (200, 201):
            # Look for base32 secrets
            for match in re.finditer(r'[A-Z2-7]{16,}', b):
                val = match.group(0)
                if len(val) >= 16 and len(val) <= 64:
                    result["secrets_found"].append({"endpoint": ep, "secret": val})

            # Look for otpauth URLs
            for match in re.finditer(r'otpauth://[^\s"\'\\]+', b):
                result["qr_urls"].append({"endpoint": ep, "url": match.group(0)})

            # Try JSON parsing
            try:
                data = json.loads(b)
                for key in ["secret", "totp_secret", "key", "seed", "otp_secret"]:
                    if key in data:
                        result["secrets_found"].append({"endpoint": ep, "key": key, "value": data[key]})
            except Exception:
                pass

    return result


# ── Full 2FA Audit ────────────────────────────────────────────────────────────

def full_2fa_audit(base_url: str, otp_endpoint: str, otp_field: str = "otp",
                   extra_fields: dict = None, cookie: str = None,
                   totp_secret: str = None) -> dict:
    """
    Complete 2FA security audit.
    """
    result = {
        "target":     base_url,
        "timestamp":  datetime.now().isoformat(),
        "findings":   [],
        "tests":      {},
        "score":      100,  # Start perfect, deduct for vulns
    }

    full_endpoint = base_url.rstrip("/") + "/" + otp_endpoint.lstrip("/")

    print(f"[*] 2FA audit: {full_endpoint}")

    print("  [1/5] Rate limit test...")
    rl = test_rate_limit(full_endpoint, otp_field, extra_fields, max_attempts=15,
                         delay=0.3, cookie=cookie)
    result["tests"]["rate_limit"] = rl
    if not rl["rate_limited"]:
        result["findings"].append({
            "severity": "HIGH",
            "finding":  "No OTP rate limiting — brute force possible",
            "detail":   f"Sent {rl['max_tested']} attempts without lockout",
        })
        result["score"] -= 30

    print("  [2/5] OTP length/format tests...")
    lt = test_otp_length(full_endpoint, otp_field, extra_fields, cookie=cookie)
    result["tests"]["length"] = lt
    for f in lt["findings"]:
        result["findings"].append({"severity": "HIGH", "finding": f, "detail": ""})
        result["score"] -= 20

    if totp_secret:
        print("  [3/5] Time window test...")
        tw = test_time_window(full_endpoint, totp_secret, otp_field, extra_fields, cookie)
        result["tests"]["time_window"] = tw
        if tw.get("max_past", 0) > 1 or tw.get("max_future", 0) > 1:
            result["findings"].append({
                "severity": "MEDIUM",
                "finding":  "Wide TOTP acceptance window",
                "detail":   tw["verdict"],
            })
            result["score"] -= 15
    else:
        result["tests"]["time_window"] = {"skipped": "totp_secret not provided"}

    print("  [4/5] TOTP secret exposure check...")
    exp = check_totp_secret_exposure(base_url, cookie=cookie)
    result["tests"]["secret_exposure"] = exp
    if exp["secrets_found"]:
        result["findings"].append({
            "severity": "CRITICAL",
            "finding":  "TOTP secret exposed in API response",
            "detail":   str(exp["secrets_found"][0]),
        })
        result["score"] -= 40

    print("  [5/5] Backup code test...")
    bc = test_backup_codes(base_url, cookie=cookie)
    result["tests"]["backup_codes"] = bc
    for f in bc["findings"]:
        result["findings"].append({"severity": "MEDIUM", "finding": f, "detail": ""})
        result["score"] -= 10

    result["score"] = max(0, result["score"])

    grade = "A" if result["score"] >= 90 else \
            "B" if result["score"] >= 75 else \
            "C" if result["score"] >= 60 else \
            "D" if result["score"] >= 45 else "F"

    result["grade"]   = grade
    result["summary"] = (
        f"2FA Security Grade: {grade} ({result['score']}/100) — "
        f"{len(result['findings'])} finding(s)"
    )

    print(f"\n  {result['summary']}")
    return result


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== otp_tester.py self-test ===\n")

    print("[1] TOTP generation:")
    # RFC 6238 test vector (SHA1, secret=JBSWY3DPEHPK3PXP)
    test_secret = "JBSWY3DPEHPK3PXP"
    codes = gen_totp_window(test_secret, window=2)
    for c in codes:
        print(f"    {c['label']:>5}: {c['code']}")

    print("\n[2] TOTP with known timestamp (RFC test):")
    # At t=59: expected code depends on secret
    code_at_59 = gen_totp(test_secret, t=59)
    print(f"    t=59: {code_at_59}")

    print("\n[3] Test rate limit against lumo-app OTP endpoint:")
    result = test_rate_limit(
        "http://localhost:3001/api/auth/resend-otp",
        otp_field="phone",
        extra_fields={"phone": "+220123456789"},
        max_attempts=8,
        delay=0.5,
    )
    print(f"    Rate limited: {result['rate_limited']}")
    print(f"    Verdict: {result['verdict']}")

    print("\nDone.")
