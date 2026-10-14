/*
 * Initial application image for the legacy-DFU CTF board.
 *
 * This source belongs to the challenge build, not the player handout.  The
 * handout is the stripped raw binary emitted by build_maintenance_application.sh.
 * The GATT adapter invokes maintenance_command() when it receives a write on
 * the board's maintenance control characteristic.  A successful request uses
 * the same GPREGRET boot reason as Nordic's SDK 11 dfu_app_handler before the
 * board is reset into the legacy bootloader.
 */

#include <stdint.h>

#define POWER_GPREGRET (*(volatile uint32_t *)0x4000051cUL)
#define BOOTLOADER_DFU_START 0xb1U
#define MAINTENANCE_REQUEST_LENGTH 7U

static const uint8_t route_key[MAINTENANCE_REQUEST_LENGTH] = {
    0x82U, 0x95U, 0xc1U, 0x37U, 0x4aU, 0xb0U, 0x6eU,
};

static const uint8_t route_check[MAINTENANCE_REQUEST_LENGTH] = {
    0x9dU, 0x8fU, 0x94U, 0x23U, 0xe8U, 0xa3U, 0xcdU,
};

static uint8_t rotl8(uint8_t value, uint8_t bits)
{
    bits &= 7U;
    if (bits == 0U) {
        return value;
    }
    return (uint8_t)((value << bits) | (value >> (8U - bits)));
}

/*
 * Kept as a named, retained symbol so the Qiling board adapter can enter the
 * application at its real Thumb code boundary.  The input transformation is
 * intentionally reversible: this is a firmware-reversing gate to discover a
 * documented maintenance-mode request, not a second cryptographic challenge.
 */
__attribute__((noinline, used, section(".text.maintenance_command")))
int maintenance_command(const uint8_t *request, uint32_t length)
{
    uint8_t mismatch = 0U;
    uint32_t index;

    if (length != MAINTENANCE_REQUEST_LENGTH) {
        return 0;
    }

    for (index = 0U; index < MAINTENANCE_REQUEST_LENGTH; ++index) {
        uint8_t transformed = rotl8(request[index], (uint8_t)(index * 3U + 1U));
        transformed ^= route_key[index];
        transformed ^= (uint8_t)(0x3dU + index * 0x11U);
        mismatch |= (uint8_t)(transformed ^ route_check[index]);
    }

    if (mismatch != 0U) {
        return 0;
    }

    POWER_GPREGRET = BOOTLOADER_DFU_START;
    return 1;
}

void Reset_Handler(void)
{
    /* BLE is provided by the board adapter in this emulation target. */
    for (;;) {
        __asm volatile("wfi");
    }
}

__attribute__((section(".isr_vector"), used))
const uintptr_t vectors[] = {
    0x20008000UL,
    (uintptr_t)Reset_Handler,
};
