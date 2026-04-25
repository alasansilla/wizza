# WiZZA Bluetooth L2CAP Fuzzing Harness — Build Instructions
#
# Requirements:
#   apt install afl++ android-tools-adb clang
#
# Workflow:
#   1. Build harness (links against Android BlueDroid stub or real stack)
#   2. Run AFL++ with seeds from seeds/bluetooth_l2cap/
#   3. Triage crashes with adb logcat

CC      = afl-clang-fast
CFLAGS  = -O2 -g -fsanitize=address,undefined
TARGET  = fuzz_bt_harness

# ── Stub build (no Android device) ───────────────────────────────────────────
# Compiles a stub l2cap_recv_frame() for local crash discovery.
# Use this to validate seeds and find parser logic bugs off-device.
stub:
	$(CC) $(CFLAGS) \
	    -DSTUB_L2CAP \
	    -x c - -o $(TARGET)_stub <<'EOF'
	    #include <stdio.h>
	    #include <stdint.h>
	    #include <string.h>
	    void l2cap_recv_frame(uint16_t handle, uint16_t cid,
	                          const uint8_t *data, size_t len) {
	        /* stub: print header fields — replace with real stack symbol */
	        if (len >= 8) {
	            uint16_t total_len = data[4] | (data[5] << 8);
	            if (total_len == 0xFFFF && len < 64) {
	                __builtin_trap(); /* simulate underflow crash */
	            }
	        }
	    }
	EOF
	$(CC) $(CFLAGS) fuzz_bt_harness.c -L. -o $(TARGET)_stub

# ── Real BlueDroid build (Android NDK) ───────────────────────────────────────
# Cross-compile for ARM64, push to rooted device, run under KernelSU.
# Requires Android NDK in PATH and afl-clang-fast built for aarch64.
NDK_TARGET = aarch64-linux-android31
NDK_CC     = $(NDK_TARGET)-clang

ndk:
	$(NDK_CC) $(CFLAGS) \
	    -I$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include \
	    fuzz_bt_harness.c \
	    -lbluetooth -o $(TARGET)_arm64
	adb push $(TARGET)_arm64 /data/local/tmp/
	adb shell "chmod +x /data/local/tmp/$(TARGET)_arm64"

# ── Run AFL++ ─────────────────────────────────────────────────────────────────
fuzz: stub
	mkdir -p findings/bluetooth_l2cap
	afl-fuzz \
	    -i ../../seeds/bluetooth_l2cap \
	    -o findings/bluetooth_l2cap \
	    -m none \
	    -- ./$(TARGET)_stub

# ── Triage crashes ────────────────────────────────────────────────────────────
triage:
	@echo "=== Unique crashes ==="
	@ls findings/bluetooth_l2cap/crashes/ 2>/dev/null | grep -v README || echo "No crashes yet"
	@echo ""
	@echo "=== To replay a crash ==="
	@echo "  ./$(TARGET)_stub < findings/bluetooth_l2cap/crashes/<id>"

clean:
	rm -f $(TARGET)_stub $(TARGET)_arm64

.PHONY: stub ndk fuzz triage clean
