/*
 * WiZZA Bluetooth L2CAP Fuzzing Harness
 * Zielt auf Android 8-15 BlueDroid/Fluoride Stack
 * Entwickelt für Zero-Click RCE Discovery
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* * Emulierter Android Bluetooth Stack Hook. 
 * Dies ist der direkte Einsprungpunkt für L2CAP-Pakete im Kernel/Stack.
 * Wir umgehen die Funk-Hardware und greifen direkt den Parser an.
 */
extern void l2cap_recv_frame(uint16_t handle, uint16_t cid, const uint8_t *data, size_t len);

/* AFL persistent mode für maximale Geschwindigkeit (zak zak) */
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 5) continue; // Zu klein für HCI + L2CAP Header

        /* * Wir parsen den mutierten Seed, den unser Python-Skript gebaut hat.
         * buf[0] ist der HCI Pakettyp (0x02 für ACL Data)
         */
        uint16_t handle = buf[1] | ((buf[2] & 0x0F) << 8); // HCI Handle
        uint16_t cid = buf[6] | (buf[7] << 8);             // L2CAP Channel ID

        /* * INJEKTION: Feuere den manipulierten Seed direkt in den Speicher!
         * Wenn AFL++ den Length-Underflow trifft, crasht dieser Aufruf.
         */
        l2cap_recv_frame(handle, cid, buf, len);
    }
    return 0;
}
