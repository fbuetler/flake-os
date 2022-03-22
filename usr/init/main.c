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
    mm_tracker_debug_print(&aos_mm.mmt);
}
/*
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
    mm_tracker_debug_print(&aos_mm.mmt);

    // left aligned
    err = aos_ram_free(outer_left_split);
    assert(err_is_ok(err));
    mm_tracker_debug_print(&aos_mm.mmt);

    // right aligned
    err = aos_ram_free(middle_split);
    assert(err_is_ok(err));
    mm_tracker_debug_print(&aos_mm.mmt);

    // normal
    err = aos_ram_free(inner_left_split);
    assert(err_is_ok(err));
    mm_tracker_debug_print(&aos_mm.mmt);

    // normal
    err = aos_ram_free(outer_right_split);
    assert(err_is_ok(err));
    mm_tracker_debug_print(&aos_mm.mmt);
}
*/

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
    mm_tracker_debug_print(&aos_mm.mmt);
    for (int i = 0; i < n; i += 2) {
        printf("Iteration %d\n", i);
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_tracker_debug_print(&aos_mm.mmt);
    for (int i = 1; i < n; i += 2) {
        printf("Iteration %d\n", i);
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_tracker_debug_print(&aos_mm.mmt);
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
    mm_tracker_debug_print(&aos_mm.mmt);
    for (int i = 0; i < n; i++) {
        printf("Iteration %d\n", i);
        err = aos_ram_free(caps[i]);
        assert(err_is_ok(err));
    }
    mm_tracker_debug_print(&aos_mm.mmt);
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
    mm_tracker_debug_print(&aos_mm.mmt);
    for (int j = 0; j < i; j++) {
        printf("Iteration %d\n", j);
        err = aos_ram_free(caps[j]);
        assert(err_is_ok(err));
    }
    mm_tracker_debug_print(&aos_mm.mmt);
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
    printf("fixing: %u", allocated_bytes);
    err = paging_map_fixed(st, vaddr, frame_cap, allocated_bytes);
    if(err_is_fail(err))
        DEBUG_ERR(err, "oh my");
    assert(err_is_ok(err));

    // increment l3 index by 1 per base page to avoid mapping conflicts
    vaddr += (1 << 13) * (allocated_bytes / (1 << 12));
}

__attribute__((unused)) static void test_slab_allocator_refill(void)
{
    printf("Pre refill free slab count: %d\n", slab_freecount(&aos_mm.slab_allocator));
    //mm_tracker_debug_print(&get_current_paging_state()->vspace_tracker);
    errval_t err = slab_default_refill(&aos_mm.slab_allocator);
    if(err_is_fail(err))
        DEBUG_ERR(err, "oh my");
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

lvaddr_t test_vtable_vaddr = VADDR_OFFSET + 0x6000000000;

__attribute__((unused)) static void test_vtable_mapping_size(gensize_t bytes)
{
    struct capref frame_cap;
    size_t allocated_bytes;

    errval_t err = frame_alloc(&frame_cap, bytes, &allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "frame_alloc");
    }
    assert(err_is_ok(err));

    assert(allocated_bytes == bytes);

    // map frame
    struct paging_state *st = get_current_paging_state();
    err = paging_map_fixed(st, test_vtable_vaddr, frame_cap, allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_fixed");
    }
    assert(err_is_ok(err));

    printf("allocated: %x\n", allocated_bytes / BASE_PAGE_SIZE);
    char *addr = (char *)test_vtable_vaddr;

    uint32_t total_pages = allocated_bytes / BASE_PAGE_SIZE - 1;

    void *last_allocated_byte = (void *)test_vtable_vaddr + bytes - 1;
    char x = 0;
    for (; addr <= (char *)last_allocated_byte; addr++) {
        if ((size_t)addr % BASE_PAGE_SIZE) {
            printf("page: %d/%d\n", (size_t)(addr - test_vtable_vaddr) / BASE_PAGE_SIZE,
                   total_pages);
        }
        *addr = x;
        assert(*addr == x++);
    }
    test_vtable_vaddr += allocated_bytes;

    mm_tracker_debug_print(&aos_mm.mmt);
    printf("test_vtable_mapping_size done\n");
}

__attribute__((unused)) static void test_many_single_pages_allocated(int iterations)
{
    lvaddr_t vaddr = VADDR_OFFSET + 0xe0000000;
    for (int i = 0; i < iterations; i++) {
        printf("iter: %d\n", i);
        // allocate a page
        struct capref frame_cap;
        errval_t err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, NULL);
        assert(err_is_ok(err));
        // map frame
        struct paging_state *st = get_current_paging_state();
        err = paging_map_fixed(st, vaddr, frame_cap, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed");
        }

        assert(err_is_ok(err));

        vaddr += BASE_PAGE_SIZE;
    }
    printf("test_many_single_pages_allocated done\n");
}

__attribute__((unused)) static void test_alloc_free(int iterations)
{
    for (int i = 0; i < iterations; i++) {
        struct capref cap;

        errval_t err = ram_alloc(&cap, BASE_PAGE_SIZE);
        assert(err_is_ok(err));

        err = aos_ram_free(cap);
        assert(err_is_ok(err));
    }

    mm_tracker_debug_print(&aos_mm.mmt);
}

__attribute__((unused)) static void test_alignments(int iterations, gensize_t alloc_size)
{
    for (int i = 1; i <= iterations; i++) {
        gensize_t alignment_bytes = i * BASE_PAGE_SIZE;
        struct capref ram_cap;
        errval_t err = ram_alloc_aligned(&ram_cap, alloc_size, alignment_bytes);
        assert(err_is_ok(err));

        struct capability c;
        // identiy cap to get RAM information out of it
        err = cap_direct_identify(ram_cap, &c);
        assert(err_is_ok(err));
        printf("%u: %u\n", c.u.ram.base, c.u.ram.base % alignment_bytes);
        assert(c.u.ram.base % alignment_bytes == 0);

        aos_ram_free(ram_cap);
    }
}

__attribute__((unused)) static void test_merge(int iterations, size_t size,
                                               size_t alignment)
{
    struct capref cap;
    errval_t err;

    for (int i = 0; i < iterations; i++) {
        err = aos_ram_alloc_aligned(&cap, size, alignment);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "error in alloc");
        }
        assert(err_is_ok(err));

        err = aos_ram_free(cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "error in free");
        }
        assert(err_is_ok(err));
    }

    mm_tracker_debug_print(&aos_mm.mmt);
}

__attribute__((unused)) static void double_free(void)
{
    struct capref cap;

    errval_t err = ram_alloc(&cap, BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    printf("first free\n");
    err = aos_ram_free(cap);
    assert(err_is_ok(err));

    printf("2nd free\n");
    err = aos_ram_free(cap);
    assert(err_is_fail(err));

    printf("double_free done\n");
}

__attribute__((unused)) static void random_patterns(int iterations)
{
#include <stdlib.h>
    srand(42);
    lvaddr_t vaddr = VADDR_OFFSET + 0xb0000000;
    for (int i = 0; i < iterations; i++) {
        // currently, assume sizes fit into a single l3 table,
        // so max number of pages at same time is 512
        size_t pages = (rand() % 512) + 1;
        gensize_t alloc_size = BASE_PAGE_SIZE * pages;
        printf("iter %d: alloc %d pages\n", i, pages);

        struct capref frame_cap;
        errval_t err = frame_alloc(&frame_cap, alloc_size, NULL);
        assert(err_is_ok(err));
        // map frame
        struct paging_state *st = get_current_paging_state();
        err = paging_map_fixed(st, vaddr, frame_cap, alloc_size);
        assert(err_is_ok(err));

        // write something at beginning and end
        int *addr = (int *)vaddr;

        *addr = 1003;
        assert(*addr == 1003);
        // end
        addr += pages * (BASE_PAGE_SIZE >> 4) - 1;
        *addr = 1004;
        assert(*addr == 1004);

        // check beginning again
        addr = (int *)vaddr;
        assert(*addr == 1003);

        vaddr += alloc_size;

        // align always to 512 * PAGE_SIZE so that we can be sure that in case we want to
        // map 512 pages at once, it all falls into the same l3 table
        vaddr = ROUND_UP(vaddr, (512 * BASE_PAGE_SIZE));
    }

    printf("random_patterns done\n");
}

__attribute__((unused)) static void test_slab_refill(void)
{
    printf("slabs pre: %d\n", slab_freecount(&aos_mm.slab_allocator));
    slab_default_refill(&aos_mm.slab_allocator);
    printf("slabs post: %d\n", slab_freecount(&aos_mm.slab_allocator));
}

__attribute__((unused)) static void test_slot_refill(void)
{
    struct slot_prealloc *slots = aos_mm.slot_allocator;

    struct capref dummy;
    for (int i = 0; i < 257; i++)
        aos_mm.slot_alloc(slots, 1, &dummy);
    printf("slots pre: %d\n",
           slots->meta[slots->current].free + slots->meta[!slots->current].free);
    assert(err_is_ok(slot_prealloc_refill(slots)));
    printf("slots post: %d\n",
           slots->meta[slots->current].free + slots->meta[!slots->current].free);
}

__attribute__((unused)) static void run_m1_tests(void)
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
    //test_partial_free();

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

    // test refilling
    test_slab_refill();
    test_slot_refill();

    // test different alignments
    test_alignments(10, 2 * BASE_PAGE_SIZE);
    test_alignments(10, 3 * BASE_PAGE_SIZE);
    test_alignments(10, 5 * BASE_PAGE_SIZE);

    // test alloc, dealloc -> merge
    test_merge(10, 2 * BASE_PAGE_SIZE, 10 * BASE_PAGE_SIZE);

    // test random alloc sizes
    // slab_refill_no_pagefault() -> LIB_ERR_NOT_IMPLEMENTED
    // random_patterns(100);

    // test freeing the same memory twice
    double_free();

    // test mapping vtables of different sizes & verify that writable/readable works
    test_vtable_mapping_size(1 * BASE_PAGE_SIZE);
    test_vtable_mapping_size(2 * BASE_PAGE_SIZE);
    test_vtable_mapping_size(8 * BASE_PAGE_SIZE);
    test_vtable_mapping_size(64 * BASE_PAGE_SIZE);

    // allocate then deallocate, 5000 times
    test_alloc_free(5000);

    // long test: allocate lots of single pages
    // slab_refill_no_pagefault() -> LIB_ERR_NOT_IMPLEMENTED
    // test_many_single_pages_allocated(50000);
    
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
    mm_tracker_debug_print(&aos_mm.mmt);
    debug_printf("Initial free slab count: %d\n", slab_freecount(&aos_mm.slab_allocator));
    debug_printf("Initial free slot count: %d\n", slot_freecount(aos_mm.slot_allocator));

    run_m1_tests();

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
