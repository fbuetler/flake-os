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

__attribute__((unused)) static void test_partial_free(void)
{
    errval_t err;

    struct capref complete;
    err = ram_alloc(&complete, 5 * BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    struct capref outer_left_split;
    err = aos_mm.slot_alloc(aos_mm.slot_allocator, 1, &outer_left_split);
    assert(err_is_ok(err));
    err = cap_retype(outer_left_split, complete, 0, aos_mm.objtype, BASE_PAGE_SIZE, 1);
    assert(err_is_ok(err));

    struct capref inner_left_split;
    err = aos_mm.slot_alloc(aos_mm.slot_allocator, 1, &inner_left_split);
    assert(err_is_ok(err));
    err = cap_retype(inner_left_split, complete, BASE_PAGE_SIZE, aos_mm.objtype,
                     BASE_PAGE_SIZE, 1);
    assert(err_is_ok(err));

    struct capref middle_split;
    err = aos_mm.slot_alloc(aos_mm.slot_allocator, 1, &middle_split);
    assert(err_is_ok(err));
    err = cap_retype(middle_split, complete, 2 * BASE_PAGE_SIZE, aos_mm.objtype,
                     BASE_PAGE_SIZE, 1);
    assert(err_is_ok(err));

    struct capref inner_right_split;
    err = aos_mm.slot_alloc(aos_mm.slot_allocator, 1, &inner_right_split);
    assert(err_is_ok(err));
    err = cap_retype(inner_right_split, complete, 3 * BASE_PAGE_SIZE, aos_mm.objtype,
                     BASE_PAGE_SIZE, 1);
    assert(err_is_ok(err));

    struct capref outer_right_split = complete;

    // memory layout
    // outer_left / inner_left / middle / inner_right / outer_right

    // middle aligned
    err = aos_ram_free(inner_right_split);
    assert(err_is_ok(err));
    mm_debug_print(&aos_mm);

    // left aligned
    err = aos_ram_free(outer_left_split);
    assert(err_is_ok(err));
    mm_debug_print(&aos_mm);

    // right aligned
    err = aos_ram_free(middle_split);
    assert(err_is_ok(err));
    mm_debug_print(&aos_mm);

    // normal
    err = aos_ram_free(inner_left_split);
    assert(err_is_ok(err));
    mm_debug_print(&aos_mm);

    // normal
    err = aos_ram_free(outer_right_split);
    assert(err_is_ok(err));
    mm_debug_print(&aos_mm);
}

__attribute__((unused)) static void test_merge_memory(size_t n, size_t size,
                                                      size_t alignment)
{
    errval_t err;
    struct capref caps[n];
    for (int i = 0; i < n; i++) {
        printf("Iteration %d\n", i);
        err = ram_alloc_aligned(&caps[i], size, alignment);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
    for (int i = 0; i < n; i += 2) {
        printf("Iteration %d\n", i);
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
    for (int i = 1; i < n; i += 2) {
        printf("Iteration %d\n", i);
        err = aos_ram_free(caps[i]);
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
        printf("Iteration %d\n", i);
        err = ram_alloc_aligned(&caps[i], size, alignment);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
    for (int i = 0; i < n; i++) {
        printf("Iteration %d\n", i);
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_debug_print(&aos_mm);
    if (size > 1 << 5) {
        printf("Note: page tables are still allocated\n");
    }
}

__attribute__((unused)) static void test_expontential_allocs_then_frees(size_t limit)
{
    // multiples of base page size
    int base_page_size_log = 12;
    limit -= base_page_size_log;

    errval_t err;
    struct capref caps[limit];
    int i;
    for (i = 0; i < limit; i++) {
        printf("Iteration %d\n", i);
        err = ram_alloc_aligned(&caps[i], 1 << (base_page_size_log + i), 1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to allocate memory");
            break;
        }
    }
    mm_debug_print(&aos_mm);
    for (int j = 0; j < i; j++) {
        printf("Iteration %d\n", j);
        err = aos_ram_free(caps[j]);
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
    printf("base: %lu\n", c0.u.ram.base);

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
    printf("base: %lu\n", c3.u.ram.base);
}

__attribute__((unused)) static void test_map_single_frame(size_t n)
{
    errval_t err;
    if (n <= 0) {
        n = 1;
    }
    size_t bytes = n * BASE_PAGE_SIZE;
    // dont interfere with the hardcoded addr in slab refill
    static lvaddr_t vaddr = VADDR_OFFSET + (1 << 20);

    struct capref frame_cap;
    size_t allocated_bytes;
    err = frame_alloc(&frame_cap, bytes, &allocated_bytes);
    assert(err_is_ok(err));

    struct paging_state *st = get_current_paging_state();
    err = paging_map_fixed(st, vaddr, frame_cap, allocated_bytes);
    assert(err_is_ok(err));

    // increment l3 index by 1 per base page to avoid mapping conflicts
    vaddr += (1 << 13) * (allocated_bytes / (1 << 12));
}

__attribute__((unused)) static void test_slab_allocator_refill(void)
{
    printf("Pre refill free slab count: %d\n", slab_freecount(&aos_mm.slab_allocator));
    errval_t err = slab_default_refill(&aos_mm.slab_allocator);
    assert(err_is_ok(err));
    printf("Post refill free slab count: %d\n", slab_freecount(&aos_mm.slab_allocator));
}

__attribute__((unused)) static void test_slot_allocator_refill(void)
{
    errval_t err;
    struct slot_prealloc *slot_allocator = aos_mm.slot_allocator;
    printf("Pre refill free slot count: %d\n", slot_freecount(slot_allocator));

    err = slot_prealloc_refill(slot_allocator);
    assert(err_is_ok(err));

    slot_allocator->current = !slot_allocator->current;  // refill both

    err = slot_prealloc_refill(slot_allocator);
    assert(err_is_ok(err));

    printf("Post refill free slot count: %d\n", slot_freecount(slot_allocator));
}

__attribute__((unused)) static void tests(void)
{
    // small tests with no alignment
    test_alternate_allocs_and_frees(8, 1 << 12, 1);
    test_merge_memory(8, 1 << 12, 1);
    test_consecutive_allocs_then_frees(8, 1 << 12, 1);

    // small tests with 4KB alignment
    test_alternate_allocs_and_frees(8, 1 << 12, 1 << 12);
    test_merge_memory(8, 1 << 12, 1 << 12);
    test_consecutive_allocs_then_frees(8, 1 << 12, 1 << 12);

    // test partial free
    test_partial_free();

    // test frame mapping
    test_map_single_frame(1);
    test_map_single_frame(4);
    test_map_single_frame(32);

    // test refills
    test_slab_allocator_refill();
    test_slot_allocator_refill();

    // big tests with no alignment
    test_alternate_allocs_and_frees(1 << 9, 1 << 12, 1);
    test_consecutive_allocs_then_frees(1 << 10, 1 << 12, 1);

    // exotic tests
    test_expontential_allocs_then_frees(31);
    // test_next_fit_alloc();
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
    debug_printf("Initial free slab count: %d\n", slab_freecount(&aos_mm.slab_allocator));
    debug_printf("Initial free slot count: %d\n", slot_freecount(aos_mm.slot_allocator));

    // tests();

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
