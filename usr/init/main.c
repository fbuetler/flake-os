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
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <grading.h>

#include "mem_alloc.h"


struct bootinfo *bi;

coreid_t my_core_id;

__attribute__((unused)) static void test_alternate_allocs_and_frees(size_t n, size_t size,
                                                                    size_t alignment)
{
    errval_t err;
    for (int i = 0; i < n; i++) {
        printf("Iteration %d\n", i);
        struct capref cap;
        err = ram_alloc_aligned(&cap, size, alignment);
        assert(err_is_ok(err));
        err = aos_ram_free(cap);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
}

__attribute__((unused)) static void
test_consecutive_allocs_then_frees(size_t n, size_t size, size_t alignment)
{
    errval_t err;
    struct capref caps[n];
    for (int i = 0; i < n; i++) {
        err = ram_alloc_aligned(&caps[i], size, alignment);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
    for (int i = 0; i < n; i++) {
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
}

__attribute__((unused)) static void test_expontential_allocs_then_frees(size_t limit)
{
    // multiples of base page size
    int base_page_size_log = 12;
    limit -= base_page_size_log;

    errval_t err;
    struct capref caps[limit];
    for (int i = 0; i < limit; i++) {
        err = ram_alloc_aligned(&caps[i], 1 << (base_page_size_log + i), 1);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
    for (int i = 0; i < limit; i++) {
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
}

__attribute__((unused)) static void test_next_fit_alloc(void)
{
    errval_t err;
    // assumes big enough continous memory region

    // allocate small
    struct capref cap0;
    err = ram_alloc(&cap0, 1 << 2);
    assert(err_is_ok(err));

    struct capability c0;
    err = cap_direct_identify(cap0, &c0);
    assert(err_is_ok(err));
    printf("base: %d\n", c0.u.ram.base);

    // allocate big 1
    struct capref cap1;
    err = ram_alloc(&cap1, 1 << 3);
    assert(err_is_ok(err));

    // free small
    err = aos_ram_free(cap0);
    assert(err_is_ok(err));

    // allocate big 1
    struct capref cap2;
    err = ram_alloc(&cap2, 1 << 3);
    assert(err_is_ok(err));

    // free small
    struct capref cap3;
    err = ram_alloc(&cap3, 1 << 2);
    assert(err_is_ok(err));

    struct capability c3;
    err = cap_direct_identify(cap3, &c3);
    assert(err_is_ok(err));
    printf("base: %d\n", c3.u.ram.base);
}

__attribute__((unused)) static void test_map_single_frame(void)
{
    errval_t err;
    size_t bytes = BASE_PAGE_SIZE;

    struct capref frame_cap;
    size_t allocated_bytes;
    err = frame_alloc(&frame_cap, bytes, &allocated_bytes);
    assert(err_is_ok(err));

    struct paging_state *st = get_current_paging_state();
    lvaddr_t vaddr = VADDR_OFFSET + 0xaaaaa000;  // M1: use a manually chosen VA offset
    err = paging_map_fixed(st, vaddr, frame_cap, allocated_bytes);
    assert(err_is_ok(err));
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
    mm_debug_print(&aos_mm);

    test_alternate_allocs_and_frees(8, 1 << 12, 1);
    test_alternate_allocs_and_frees(8, 1 << 12, 1 << 12);
    test_consecutive_allocs_then_frees(8, 1 << 12, 1);
    test_consecutive_allocs_then_frees(8, 1 << 12, 1 << 12);
    // test_alternate_allocs_and_frees(1 << 10);
    // test_consecutive_allocs_then_frees(1 << 10);
    // test_next_fit_alloc();
    // test_expontential_allocs_then_frees(20);

    test_map_single_frame();

    // err = slab_default_refill(&aos_mm.slabs);
    // assert(err_is_ok(err));

    // TODO write test to exhaust slab and slot allocators to test page mappings

    // TODO: initialize mem allocator, vspace management here

    // setup CSpace: L1CNode, L2CNode
    // L1CNode (cnode_create_l1): initially 256 slots with L2CNodes,
    // but can be extended with 'root_cnode_resize()'
    // L1Code (cnode_create_l2): fixed size of 256 slots

    // Grading
    grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here

    // Grading
    grading_test_late();

    debug_printf("Message handler loop\n");
    // Hang around
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
    return LIB_ERR_NOT_IMPLEMENTED;
}


int main(int argc, char *argv[])
{
    errval_t err;


    /* Set the core id in the disp_priv struct */
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    assert(err_is_ok(err));
    disp_set_core_id(my_core_id);

    debug_printf("init: on core %" PRIuCOREID ", invoked as:", my_core_id);
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
