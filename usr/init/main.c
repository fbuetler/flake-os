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

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <grading.h>
#include <spawn/spawn.h>
#include <aos/coreboot.h>

#include "mem_alloc.h"
#include "custom_tests.h"


struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;

static errval_t boot_core(coreid_t core_id)
{
    errval_t err;

    const char *boot_driver = "boot_armv8_generic";
    const char *cpu_diver = "cpu_a57_qemu";
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

    coreboot(core_id, boot_driver, cpu_diver, init, urpc_frame_id);

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

    spawn_init();

    // setup endpoint of init
    lmp_chan_init(&init_spawninfo.rpc.chan);

    err = lmp_endpoint_create_in_slot(512, cap_initep, &init_spawninfo.rpc.chan.endpoint);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed create endpoint in init process");
        abort();
    }
    init_spawninfo.rpc.chan.buflen_words = 256;

    // run_m1_tests();
    // run_m2_tests();
    // run_m3_tests();
    // run_m4_tests();

    // TODO: Spawn system processes, boot second core etc. here
    err = boot_core(1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }
    err = boot_core(2);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }
    err = boot_core(3);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }

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

static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();
    DEBUG_PRINTF("hello from core %d :)\n", disp_get_core_id());
    return LIB_ERR_NOT_IMPLEMENTED;
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

    fflush(stdout);

    if (my_core_id == 0)
        return bsp_main(argc, argv);
    else
        return app_main(argc, argv);
}
