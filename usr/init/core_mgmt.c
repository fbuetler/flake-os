#include <stdio.h>
#include <stdlib.h>

#include "core_mgmt.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/aos_ump.h>
#include <aos/coreboot.h>

#include "init_ump.h"
#include "mem_alloc.h"

extern struct platform_info platform_info;

static errval_t send_cap(struct aos_ump *ump, enum aos_rpc_msg_type msg_type,
                         struct capref cap)
{
    errval_t err;

    struct ump_mem_msg region;
    err = get_phys_addr(cap, &region.base, &region.bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get physical address");
        return err;
    }

    err = aos_ump_send(ump, msg_type, (char *)&region, sizeof(region));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send cap to other core");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t recv_cap(struct aos_ump *ump, aos_rpc_msg_type_t expected_msg_type,
                         struct ump_mem_msg **mem_msg)
{
    errval_t err;

    aos_rpc_msg_type_t msg_type;
    char *payload;
    size_t payload_len;
    err = aos_ump_receive(ump, &msg_type, &payload, &payload_len);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive cap");
        return err_push(err, LIB_ERR_UMP_RECV);
    }

    assert(msg_type == expected_msg_type);
    *mem_msg = (struct ump_mem_msg *)payload;

    return SYS_ERR_OK;
}

errval_t boot_core(coreid_t core_id)
{
    errval_t err;

    const char *boot_driver = "boot_armv8_generic";
    const char *cpu_driver;
    switch (platform_info.platform) {
    case PI_PLATFORM_QEMU:
        cpu_driver = "cpu_a57_qemu";
        break;
    case PI_PLATFORM_IMX8X:
        cpu_driver = "cpu_imx8x";
        break;
    default:
        return LIB_ERR_NOT_IMPLEMENTED;
    }
    const char *init = "init";

    struct aos_ump *ump = &aos_ump_server_chans[core_id];
    struct aos_ump *c_ump = &aos_ump_client_chans[core_id];

    size_t allocated_bytes;
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, 2 * BASE_PAGE_SIZE, &allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate frame\n");
        return err;
    }

    void *urpc;
    err = paging_map_frame_complete(get_current_paging_state(), &urpc, frame_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map urpc frame");
        return err;
    }

    // init channel
    err = aos_ump_initialize(ump, urpc, true);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to initialize channel");
        return err;
    }

    aos_ump_initialize(c_ump, urpc + BASE_PAGE_SIZE, false);

    struct frame_identity urpc_frame_id;
    err = frame_identify(frame_cap, &urpc_frame_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to identify frame");
        return err;
    }

    coreboot(core_id, boot_driver, cpu_driver, init, urpc_frame_id);

    // Send Memory Almosen
    // DEBUG_PRINTF("Send initial memory\n");
    struct capref mem_cap;
    err = ram_alloc(&mem_cap, BIT(29));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "We are memory poor\n");
        return err_push(err, LIB_ERR_RAM_ALLOC);
    }

    err = send_cap(c_ump, AosRpcRamCapRequest, mem_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send mem cap");
        return err;
    }

    // Send boot info
    // DEBUG_PRINTF("Send boot info\n");
    err = send_cap(c_ump, AosRpcSendBootinfo, cap_bootinfo);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send boot info cap");
        return err;
    }

    // Send multiboot module string area
    // DEBUG_PRINTF("Send mm strings\n");
    err = send_cap(c_ump, AosRpcSendMMStrings, cap_mmstrings);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send mm strings cap");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t init_app_core(void)
{
    errval_t err;

    void *urpc;
    err = paging_map_frame_complete(get_current_paging_state(), &urpc, cap_urpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map urpc frame");
        return err;
    }

    // init channel to core0
    struct aos_ump *c_ump = &aos_ump_client_chans[0];
    struct aos_ump *ump = &aos_ump_server_chans[0];
    aos_ump_initialize(c_ump, urpc, false);
    aos_ump_initialize(ump, urpc + BASE_PAGE_SIZE, true);

    // Receive memory almosen
    // DEBUG_PRINTF("Receive initial memory\n");
    struct ump_mem_msg *memory_region;
    err = recv_cap(ump, AosRpcRamCapRequest, &memory_region);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive cap");
        return err;
    }

    struct capref mem_cap = { .cnode = cnode_super, .slot = 0 };
    err = ram_forge(mem_cap, memory_region->base, memory_region->bytes,
                    disp_get_current_core_id());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error forging cap \n");
        return err;
    }

    err = initialize_ram_alloc_from_cap(mem_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to initialize memory allocator from passed mem cap");
        return err;
    }

    // create the module cnode (for boot modules and mm_strings)
    struct capref module_cnode = { .cnode = cnode_root, .slot = ROOTCN_SLOT_MODULECN };
    err = cnode_create_raw(module_cnode, NULL, ObjType_L2CNode, L2_CNODE_SLOTS, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create module cnode");
        return err;
    }

    // Receive boot info
    // DEBUG_PRINTF("Receive boot info\n");
    struct ump_mem_msg *bootinfo_region;
    err = recv_cap(ump, AosRpcSendBootinfo, &bootinfo_region);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive cap");
        return err;
    }

    err = frame_forge(cap_bootinfo, bootinfo_region->base, bootinfo_region->bytes,
                      disp_get_current_core_id());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge frame");
        return err;
    }

    err = paging_map_frame_complete(get_current_paging_state(), (void **)&bi,
                                    cap_bootinfo);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map bootinfo frame");
        return err;
    }
    assert(bi != NULL);

    for (int i = 0; i < bi->regions_length; ++i) {
        if (bi->regions[i].mr_type == RegionType_Module) {
            struct capref module_cap = { .cnode = cnode_module,
                                         .slot = bi->regions[i].mrmod_slot };
            err = frame_forge(module_cap, bi->regions[i].mr_base,
                              ROUND_UP(bi->regions[i].mrmod_size, BASE_PAGE_SIZE),
                              disp_get_current_core_id());
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed tp forge module frame");
                return err;
            }
        }
    }

    // Receive multiboot module string area
    // DEBUG_PRINTF("Receive mm strings\n");
    struct ump_mem_msg *mmstring_region;
    err = recv_cap(ump, AosRpcSendMMStrings, &mmstring_region);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive cap");
        return err;
    }

    err = frame_forge(cap_mmstrings, mmstring_region->base, mmstring_region->bytes,
                      disp_get_current_core_id());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to force mmstring frame");
        return err;
    }

    // DEBUG_PRINTF("App core initialized\n");

    return SYS_ERR_OK;
}

errval_t cpu_off(void)
{
    DEBUG_PRINTF("turning CPU OFF\n");
    errval_t err;
    err = invoke_monitor_cpu_off();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to turn cpu off");
        return err;
    }
    DEBUG_PRINTF("turned CPU OFF\n");

    return SYS_ERR_OK;
}

errval_t cpu_on(hwid_t core_id)
{
    DEBUG_PRINTF("turning CPU ON\n");
    errval_t err;
    err = boot_core(core_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }
    DEBUG_PRINTF("turned CPU ON\n");

    return SYS_ERR_OK;
}