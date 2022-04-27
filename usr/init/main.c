/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>


#include "proc_mgmt.h"
#include "init_ump.h"
#include "init_rpc.h"

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <aos/ump_chan.h>
#include <mm/mm.h>
#include <grading.h>
#include <spawn/spawn.h>
#include <aos/coreboot.h>
#include <aos/kernel_cap_invocations.h>

#include <barrelfish_kpi/startup_arm.h>
#include <aos/deferred.h>

#include "mem_alloc.h"
#include "custom_tests.h"


struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;

static errval_t send_cap(struct ump_chan *ump, enum ump_msg_type msg_type,
                         struct capref cap)
{
    errval_t err;

    struct ump_mem_msg region;
    err = get_phys_addr(cap, &region.base, &region.bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get physical address");
        return err;
    }

    err = ump_send(ump, msg_type, (char *)&region, sizeof(region));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send cap to other core");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t recv_cap(struct ump_chan *ump, enum ump_msg_type expected_msg_type,
                         struct ump_mem_msg **mem_msg)
{
    errval_t err;

    enum ump_msg_type msg_type;
    char *payload;
    size_t payload_len;
    err = ump_receive(ump, &msg_type, &payload, &payload_len);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive cap");
        return err_push(err, LIB_ERR_UMP_RECV);
    }

    assert(msg_type == expected_msg_type);
    *mem_msg = (struct ump_mem_msg *)payload;

    return SYS_ERR_OK;
}

static errval_t boot_core(coreid_t core_id)
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

    struct capref frame_cap;
    size_t allocated_bytes;
    err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, &allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate frame");
        return err;
    }

    if (allocated_bytes != BASE_PAGE_SIZE) {
        err = LIB_ERR_FRAME_ALLOC;
        DEBUG_ERR(err, "failed to allocate frame of the requested size");
        return err;
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(frame_cap, &urpc_frame_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to identify frame");
        return err;
    }

    coreboot(core_id, boot_driver, cpu_driver, init, urpc_frame_id);

    // communicate with other core over shared memory
    void *urpc;
    err = paging_map_frame_complete(get_current_paging_state(), &urpc, frame_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map urpc frame");
    }

    // init channel
    struct ump_chan *ump = &ump_chans[core_id];
    ump_initialize(ump, urpc, true);

    // Send Memory Almosen
    DEBUG_PRINTF("Send initial memory\n");
    struct capref mem_cap;
    err = ram_alloc(&mem_cap, BIT(29));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "We are memory poor\n");
        return err_push(err, LIB_ERR_RAM_ALLOC);
    }

    err = send_cap(ump, UmpSendMem, mem_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send mem cap");
        return err;
    }

    // Send boot info
    DEBUG_PRINTF("Send boot info\n");
    err = send_cap(ump, UmpSendBootinfo, cap_bootinfo);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send boot info cap");
        return err;
    }

    // Send multiboot module string area
    DEBUG_PRINTF("Send mm strings\n");
    err = send_cap(ump, UmpSendMMStrings, cap_mmstrings);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send mm strings cap");
        return err;
    }

    return SYS_ERR_OK;
}


static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
    }

    // TODO: initialize mem allocator, vspace management here

    // Grading
    grading_test_early();

    // run_m1_tests();
    // run_m2_tests();
    // run_m3_tests();
    // run_m4_tests();

    // TODO: Spawn system processes, boot second core etc. here
    err = boot_core(1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }
    // err = boot_core(2);
    // if (err_is_fail(err)) {
    //     DEBUG_ERR(err, "failed to boot core");
    // }
    // err = boot_core(3);
    // if (err_is_fail(err)) {
    //     DEBUG_ERR(err, "failed to boot core");
    // }

    run_m5_tests_bsp();

    // Grading
    grading_test_late();

    DEBUG_PRINTF("Message handler loop\n");
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}

static errval_t aos_cpu_off(void)
{
    DEBUG_PRINTF("turning CPU OFF\n")
    errval_t err;
    err = invoke_monitor_cpu_off();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to turn cpu off");
        return err;
    }
    DEBUG_PRINTF("turned CPU OFF\n")

    return SYS_ERR_OK;
}

static errval_t init_app_core(void)
{
    errval_t err;

    void *urpc;
    err = paging_map_frame_complete(get_current_paging_state(), &urpc, cap_urpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map urpc frame");
        return err;
    }

    // init channel to core0
    struct ump_chan *ump = &ump_chans[0];
    ump_initialize(ump, urpc, false);

    // Receive memory almosen
    DEBUG_PRINTF("Receive initial memory\n");
    struct ump_mem_msg *memory_region;
    err = recv_cap(ump, UmpSendMem, &memory_region);
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
    DEBUG_PRINTF("Receive boot info\n");
    struct ump_mem_msg *bootinfo_region;
    err = recv_cap(ump, UmpSendBootinfo, &bootinfo_region);
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
    DEBUG_PRINTF("Receive mm strings\n");
    struct ump_mem_msg *mmstring_region;
    err = recv_cap(ump, UmpSendMMStrings, &mmstring_region);
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

    DEBUG_PRINTF("App core initialized\n");

    return SYS_ERR_OK;
}

static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();
    errval_t err;

    err = init_app_core();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init app core");
        abort();
    }

    grading_setup_app_init(bi);

    grading_test_early();

    struct thread *ump_listener_thread = run_ump_listener_thread();

    run_m5_tests_app();

    grading_test_late();

    aos_cpu_off();

    DEBUG_PRINTF("Message handler loop\n");
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }


    int ump_listener_retval;
    thread_join(ump_listener_thread, &ump_listener_retval);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    errval_t err;

    /* obtain the core information from the kernel*/
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the core id from the kernel\n");
    }

    /* Set the core id in the disp_priv struct */
    disp_set_core_id(my_core_id);

    /* obtain the platform information */
    err = invoke_kernel_get_platform_info(cap_kernel, &platform_info);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the platform info from the kernel\n");
    }

    char *platform;
    switch (platform_info.platform) {
    case PI_PLATFORM_QEMU:
        platform = "QEMU";
        break;
    case PI_PLATFORM_IMX8X:
        platform = "IMX8X";
        break;
    default:
        platform = "UNKNOWN";
    }

    DEBUG_PRINTF("init domain starting on core %" PRIuCOREID " (%s), invoked as:",
                 my_core_id, platform);
    for (int i = 0; i < argc; i++) {
        printf(" %s", argv[i]);
    }
    printf("\n");

    spawn_init();

    fflush(stdout);

    if (my_core_id == 0)
        return bsp_main(argc, argv);
    else
        return app_main(argc, argv);
}
