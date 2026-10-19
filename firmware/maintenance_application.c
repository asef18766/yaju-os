/*
 * Initial application image for the legacy-DFU CTF board.
 *
 * This source belongs to the challenge build, not the player handout.  The
 * handout is the stripped raw binary emitted by build_maintenance_application.sh.
 * Bumble supplies the emulated S130 transport, but the animation service is
 * registered through the real S130 GATTS ABI below.  UUID registration,
 * characteristic metadata, read authorization, frame bytes, and playback
 * state all execute as compiled Thumb firmware.
 */

#include <stdint.h>
#include <stddef.h>

#include "ble.h"
#include "ble_gatts.h"
#include "nrf_error.h"

#define POWER_GPREGRET (*(volatile uint32_t *)0x4000051cUL)
#define BOOTLOADER_DFU_START 0xb1U
#define MAINTENANCE_REQUEST_LENGTH 7U
#define ANIMATION_FRAME_SIZE 125U
#define ANIMATION_FRAME_COUNT 54U
#define ANIMATION_POSE_COUNT 10U
#define ANIMATION_SERVICE_UUID 0x1001U
#define ANIMATION_FRAME_UUID 0x1002U

static const uint8_t route_key[MAINTENANCE_REQUEST_LENGTH] = {
    0x82U, 0x95U, 0xc1U, 0x37U, 0x4aU, 0xb0U, 0x6eU,
};

static const uint8_t route_check[MAINTENANCE_REQUEST_LENGTH] = {
    0x9dU, 0x8fU, 0x94U, 0x23U, 0xe8U, 0xa3U, 0xcdU,
};

/* Nordic stores vendor bases little-endian and substitutes bytes 12..13. */
static const ble_uuid128_t animation_base_uuid = {{
    0x6dU, 0x8bU, 0xd5U, 0xc1U, 0x86U, 0xa7U, 0x2cU, 0x94U,
    0x8dU, 0x4cU, 0x5dU, 0x7cU, 0x00U, 0x00U, 0x1cU, 0x5aU,
}};

/* Ten unique poses; the timeline below supplies the intentional holds. */
static const uint8_t animation_poses[ANIMATION_POSE_COUNT][ANIMATION_FRAME_SIZE] = {
    /* head */
    {
        "                 \n"
        "       <o>       \n"
        "        |        \n"
        "        |        \n"
        "       / \\       \n"
        "      /   \\      \n"
        "     _|   |_     "
    },
    /* head_left */
    {
        "                 \n"
        "      <o>        \n"
        "       \\         \n"
        "        |        \n"
        "       / \\       \n"
        "      |  |       \n"
        "     _|  |_      "
    },
    /* head_down */
    {
        "                 \n"
        "                 \n"
        "       <o>       \n"
        "        |        \n"
        "      _/ \\_      \n"
        "      |   |      \n"
        "     _|   |_     "
    },
    /* head_right */
    {
        "                 \n"
        "        <o>      \n"
        "         /       \n"
        "        |        \n"
        "       / \\       \n"
        "       |  |      \n"
        "      _|  |_     "
    },
    /* release */
    {
        "                 \n"
        "       \\o/       \n"
        "        |        \n"
        "        |        \n"
        "       / \\       \n"
        "      /   \\      \n"
        "     _|   |_     "
    },
    /* ready */
    {
        "                 \n"
        "        o        \n"
        "       /|\\       \n"
        "       b|d       \n"
        "       / \\       \n"
        "      /   \\      \n"
        "     _|   |_     "
    },
    /* thumbs */
    {
        "                 \n"
        "        o        \n"
        "      b/|\\d      \n"
        "        |        \n"
        "       / \\       \n"
        "      /   \\      \n"
        "     _|   |_     "
    },
    /* thumbs_down */
    {
        "                 \n"
        "                 \n"
        "        o        \n"
        "      b/|\\d      \n"
        "      _/ \\_      \n"
        "      |   |      \n"
        "     _|   |_     "
    },
    /* thumbs_in */
    {
        "                 \n"
        "        o        \n"
        "      b/|\\d      \n"
        "        |        \n"
        "       / \\       \n"
        "       | |       \n"
        "      _| |_      "
    },
    /* ready_in */
    {
        "                 \n"
        "        o        \n"
        "       /|\\       \n"
        "       b|d       \n"
        "       / \\       \n"
        "       | |       \n"
        "      _| |_      "
    },
};

static const uint8_t animation_timeline[ANIMATION_FRAME_COUNT] = {
    0U, 0U, 0U, 1U, 1U, 0U, 2U, 2U, 0U, 3U, 3U, 0U, 0U, 4U,
    5U, 6U, 6U, 6U, 7U, 7U, 6U, 8U, 8U, 9U, 5U, 4U, 0U, 0U,
    0U, 3U, 3U, 0U, 2U, 2U, 0U, 1U, 1U, 0U, 0U, 4U, 5U, 6U,
    6U, 6U, 8U, 8U, 6U, 7U, 7U, 6U, 5U, 4U, 0U, 0U,
};

static uint8_t animation_next_frame;
static uint8_t animation_snapshot[ANIMATION_FRAME_SIZE];
static uint8_t animation_uuid_type;
static uint16_t animation_service_handle;
static ble_gatts_char_handles_t animation_frame_handles;

static void copy_bytes(uint8_t *destination, const uint8_t *source, uint32_t length)
{
    uint32_t index;
    for (index = 0U; index < length; ++index) {
        destination[index] = source[index];
    }
}

/* Freestanding aggregate initialization emitted by GCC uses this helper. */
void *memset(void *destination, int value, size_t length)
{
    volatile uint8_t *output = (volatile uint8_t *)destination;
    size_t index;

    for (index = 0U; index < length; ++index) {
        output[index] = (uint8_t)value;
    }
    return destination;
}

static void animation_select_pose(uint8_t pose)
{
    copy_bytes(animation_snapshot, animation_poses[pose], ANIMATION_FRAME_SIZE);
}

static void animation_reset(void)
{
    animation_next_frame = 0U;
    animation_select_pose(animation_timeline[0]);
}

static void animation_advance(void)
{
    animation_select_pose(animation_timeline[animation_next_frame]);
    ++animation_next_frame;
    if (animation_next_frame == ANIMATION_FRAME_COUNT) {
        animation_next_frame = 0U;
    }
}

static uint32_t animation_service_init(void)
{
    ble_uuid_t service_uuid = {0};
    ble_uuid_t frame_uuid = {0};
    ble_gatts_char_md_t char_md = {0};
    ble_gatts_attr_md_t attr_md = {0};
    ble_gatts_attr_t attr_value = {0};
    uint32_t result;

    animation_reset();
    result = sd_ble_uuid_vs_add(&animation_base_uuid, &animation_uuid_type);
    if (result != NRF_SUCCESS) {
        return result;
    }

    service_uuid.type = animation_uuid_type;
    service_uuid.uuid = ANIMATION_SERVICE_UUID;
    result = sd_ble_gatts_service_add(
        BLE_GATTS_SRVC_TYPE_PRIMARY,
        &service_uuid,
        &animation_service_handle
    );
    if (result != NRF_SUCCESS) {
        return result;
    }

    char_md.char_props.read = 1U;
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_USER;
    attr_md.rd_auth = 1U;
    attr_md.wr_auth = 0U;
    attr_md.vlen = 0U;

    frame_uuid.type = animation_uuid_type;
    frame_uuid.uuid = ANIMATION_FRAME_UUID;
    attr_value.p_uuid = &frame_uuid;
    attr_value.p_attr_md = &attr_md;
    attr_value.init_len = ANIMATION_FRAME_SIZE;
    attr_value.init_offs = 0U;
    attr_value.max_len = ANIMATION_FRAME_SIZE;
    attr_value.p_value = animation_snapshot;

    return sd_ble_gatts_characteristic_add(
        animation_service_handle,
        &char_md,
        &attr_value,
        &animation_frame_handles
    );
}

__attribute__((noinline, used, section(".text.firmware_api.application_init")))
uint32_t application_init(void)
{
    return animation_service_init();
}

__attribute__((noinline, used, section(".text.firmware_api.application_ble_evt")))
void application_ble_evt(const ble_evt_t *event)
{
    const ble_gatts_evt_rw_authorize_request_t *request;
    ble_gatts_rw_authorize_reply_params_t reply = {0};

    if (event == (const ble_evt_t *)0) {
        return;
    }
    if (event->header.evt_id == BLE_GAP_EVT_CONNECTED) {
        animation_reset();
        return;
    }
    if (event->header.evt_id != BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST) {
        return;
    }

    request = &event->evt.gatts_evt.params.authorize_request;
    if (request->type != BLE_GATTS_AUTHORIZE_TYPE_READ ||
        request->request.read.handle != animation_frame_handles.value_handle) {
        return;
    }

    reply.type = BLE_GATTS_AUTHORIZE_TYPE_READ;
    if (request->request.read.offset > ANIMATION_FRAME_SIZE) {
        reply.params.read.gatt_status = BLE_GATT_STATUS_ATTERR_INVALID_OFFSET;
    } else {
        if (request->request.read.offset == 0U) {
            animation_advance();
        }
        reply.params.read.gatt_status = BLE_GATT_STATUS_SUCCESS;
        reply.params.read.update = 1U;
        reply.params.read.offset = 0U;
        reply.params.read.len = ANIMATION_FRAME_SIZE;
        reply.params.read.p_data = animation_snapshot;
    }
    (void)sd_ble_gatts_rw_authorize_reply(
        event->evt.gatts_evt.conn_handle,
        &reply
    );
}

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
    (void)application_init();
    for (;;) {
        __asm volatile("wfi");
    }
}

__attribute__((section(".isr_vector"), used))
const uintptr_t vectors[] = {
    0x20008000UL,
    (uintptr_t)Reset_Handler,
};
