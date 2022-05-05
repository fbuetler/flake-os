/**
 * \file
 * \brief custom e2e tests
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include "core_mgmt.h"
#include "proc_mgmt.h"
#include "init_ump.h"
#include "init_rpc.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/deferred.h>
#include <aos/morecore.h>
#include <aos/coreboot.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <spawn/spawn.h>

#include "custom_tests.h"
#include "mem_alloc.h"

struct mm aos_mm;

/*
    M1 TEST START
*/

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

    struct capref frame_cap;
    size_t allocated_bytes;
    err = frame_alloc(&frame_cap, bytes, &allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate frame");
    }
    assert(err_is_ok(err));

    struct paging_state *st = get_current_paging_state();

    void *buf;
    err = paging_map_frame(st, &buf, allocated_bytes, frame_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to single map frame");
    }

    assert(err_is_ok(err));
}

__attribute__((unused)) static void test_slab_allocator_refill(void)
{
    printf("Pre refill free slab count: %d\n", slab_freecount(&aos_mm.slab_allocator));
    // mm_tracker_debug_print(&get_current_paging_state()->vspace_tracker);
    errval_t err = slab_default_refill(&aos_mm.slab_allocator);
    if (err_is_fail(err))
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

__attribute__((unused)) static void test_vtable_mapping_size(gensize_t bytes)
{
    assert(bytes % BASE_PAGE_SIZE == 0);

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

    char *addr;

    err = paging_map_frame(st, (void **)&addr, allocated_bytes, frame_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_frame");
    }
    assert(err_is_ok(err));

    uint32_t total_pages = allocated_bytes / BASE_PAGE_SIZE - 1;

    char *last_allocated_byte = addr + allocated_bytes - 1;
    char *base_addr = addr;
    char x = 0;
    for (; addr <= (char *)last_allocated_byte; addr++) {
        if ((size_t)addr % BASE_PAGE_SIZE == 0) {
            printf("page: %d/%d\n", (size_t)(addr - base_addr) / BASE_PAGE_SIZE,
                   total_pages);
        }
        *addr = x;
        assert(*addr == x++);
    }

    mm_tracker_debug_print(&aos_mm.mmt);
    printf("test_vtable_mapping_size done\n");
}

__attribute__((unused)) static void test_many_single_pages_allocated(int iterations)
{
    for (int i = 0; i < iterations; i++) {
        printf("iter: %d\n", i);
        // allocate a page
        struct capref frame_cap;
        errval_t err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, NULL);
        assert(err_is_ok(err));
        // map frame
        struct paging_state *st = get_current_paging_state();
        void *buf;
        err = paging_map_frame(st, &buf, BASE_PAGE_SIZE, frame_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_frame");
        }

        assert(err_is_ok(err));
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

        void *vaddr;
        err = paging_map_frame(st, &vaddr, alloc_size, frame_cap);
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

void run_m1_tests(void)
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
    // test_partial_free();

    // test frame mapping
    test_map_single_frame(1);
    test_map_single_frame(4);
    test_map_single_frame(32);

    // map across multiple l3 tables
    test_map_single_frame(4096);

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
    random_patterns(100);

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
    test_many_single_pages_allocated(40000);

    printf("Completed %s\n", __func__);
}

/*
    M2 TEST START
*/

__attribute__((unused)) static void test_spawn_single_process(void)
{
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    errval_t err = start_process("hello", si, pid);
    assert(err_is_ok(err));
}

__attribute__((unused)) static void test_spawn_multiple_processes(size_t n)
{
    errval_t err;
    struct spawninfo *sis = malloc(n * sizeof(struct spawninfo));
    domainid_t *pids = malloc(n * sizeof(domainid_t));
    for (int i = 0; i < n; i++) {
        printf("Spawn iteration %d\n", i);
        err = spawn_load_by_name("hello", &sis[i], &pids[i]);

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "spawn error");
        }
        assert(err_is_ok(err));

        spawn_print_processes();
    }

    // TODO these frees will lead to bugs in later tests, because they are still in
    // process list!
    /*free(sis);
    free(pids);*/
}


__attribute__((unused)) static void test_spawn_and_kill_single_process(void)
{
    errval_t err;

    struct spawninfo *sis = malloc(1 * sizeof(struct spawninfo));
    domainid_t *pids = malloc(1 * sizeof(struct spawninfo));

    err = spawn_load_by_name("infinite_print", sis, pids);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "spawn error");
    }
    assert(err_is_ok(err));

    spawn_print_processes();

    double x = 0;
    for (int i = 0; i < 1 << 24; i++) {
        x += i * x * 10;
    }

    printf("%f\n", x);
    spawn_kill_process(*pids);
    printf("process killed\n");
    spawn_print_processes();

    free(sis);
    free(pids);
}

__attribute__((unused)) static void test_spawn_and_kill_multiple_process(size_t n)
{
    errval_t err;

    struct spawninfo *sis = malloc(n * sizeof(struct spawninfo));
    domainid_t *pids = malloc(n * sizeof(struct spawninfo));

    for (int j = 0; j < n; j++) {
        err = spawn_load_by_name("infinite_print", &sis[j], &pids[j]);

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "spawn error");
        }
        assert(err_is_ok(err));

        spawn_print_processes();

        double x = 0;
        for (int i = 0; i < 1 << 22; i++) {
            x += i * x * 10;
        }
        printf("%f\n", x);
        spawn_kill_process(pids[j]);
        printf("process with PID 0x%lx killed\n", pids[j]);
        spawn_print_processes();
    }
}


__attribute__((unused)) static void test_paging_unmap(size_t size)
{
    struct paging_state *st = get_current_paging_state();


    errval_t err;

    void *vaddr = (void *)0x7ffffffff000;

    struct capref frame;

    err = frame_alloc(&frame, size, NULL);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_FRAME_ALLOC);
        DEBUG_ERR(err, "Failed to allocate frame of size %#x", size);
    }
    assert(err_is_ok(err));

    for (int i = 0; i < 2; i++) {
        err = paging_map_fixed_attr(st, (lvaddr_t)vaddr, frame, size,
                                    VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_PAGING_MAP);
            DEBUG_ERR(err, "Failed to map frame of size %#x at %p in the %d iteration\n",
                      size, vaddr, i);
        }
        assert(err_is_ok(err));

        printf("trying to map same frame again: iter %d\n", i);
        err = paging_map_fixed_attr(st, (lvaddr_t)vaddr, frame, size,
                                    VREGION_FLAGS_READ_WRITE);
        if (err_is_ok(err)) {
            err = err_push(err, LIB_ERR_PAGING_MAP);
            DEBUG_ERR(err,
                      "Was able to map frame of size %#x at %p in iteration %d without "
                      "unmapping first!\n",
                      size, vaddr, i);
        } else {
            DEBUG_PRINTF("Failure expected\n");
        }
        assert(err_is_fail(err));

        printf("unmap frame: iter %d\n", i);
        err = paging_unmap(st, vaddr);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_PAGING_UNMAP);
            DEBUG_ERR(err, "Failed to unmap frame of size %#x at %p in iteration %d\n",
                      size, vaddr, i);
        }
        assert(err_is_ok(err));
    }
    printf("%s successful!\n", __func__);
}


__attribute__((unused)) static void run_demo_m2(void)
{
    // Show your implementation of paging_map_frame_attr is correct by
    // mapping a large frame.

    // demo 1: map across multiple l3 tables: 4096 * BASE_PAGE_SIZE memory
    // test_map_single_frame(4096);

    // demo 2: unmap frames (make sure you uncomment the debug prints for creating page tables)
    test_paging_unmap(BIT(25));

    // demo 3: multiple processes, started at same time
    // test_spawn_multiple_processes(200);

    // demo 4: start and kill in a loop
    // test_spawn_multiple_processes(2);
    // test_spawn_and_kill_multiple_process(200);
}

void run_m2_tests(void)
{
    // spawn processes
    test_spawn_single_process();
    test_spawn_multiple_processes(2);
    // test_spawn_multiple_processes(4);
    // test_spawn_multiple_processes(5);
    test_spawn_multiple_processes(20);

    // spawn and kill a process
    test_spawn_and_kill_single_process();
    // test_spawn_and_kill_multiple_process(2);
    test_spawn_and_kill_multiple_process(20);

    printf("Completed %s\n", __func__);
}

/*
    M2 TEST START
*/

__attribute__((unused)) static void test_spawn_process(char *binary)
{
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    errval_t err = start_process(binary, si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn %s\n", binary);
    }
    assert(err_is_ok(err));
}

__attribute__((unused)) static void test_spawn_memeater(void)
{
    test_spawn_process("memeater");
}

__attribute__((unused)) static void test_spawn_multiple_memeaters(void)
{
    for (int i = 0; i < 5; i++) {
        struct spawninfo *si = malloc(sizeof(struct spawninfo));
        domainid_t *pid = malloc(sizeof(domainid_t));
        errval_t err = start_process("memeater", si, pid);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to spawn memeater");
        }
        assert(err_is_ok(err));
    }
}

/*
__attribute__((unused)) static void test_get_number(void)
{
    errval_t err;

    uintptr_t num;
    printf("Testing recv number ... \n");
    err = aos_rpc_get_number(&init_spawninfo.rpc, &num);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in recieving number in init \n");
        assert(false);
    }
    printf("Recieved number %d \n", num);
    assert(num == 42);

    printf("Recv number successful! \n");

    printf("Testing recv small string ... \n");

    char *recv_str;
    err = aos_rpc_get_string(&init_spawninfo.rpc, &recv_str);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in recieving string in init \n");
        assert(false);
    }
    printf("Recieved string \"%s\" \n", recv_str);

    printf("Small string success! \n");

    printf("Testing recv big string ... \n");

    char *recv_big_str;
    err = aos_rpc_get_string(&init_spawninfo.rpc, &recv_big_str);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in recieving string in init \n");
        assert(false);
    }
    printf("Recieved string \"%s\" \n", recv_big_str);

    printf("Big string success! \n");
}*/

void run_m3_tests(void)
{
    test_spawn_memeater();
    // test_spawn_multiple_memeaters();
    // test_get_number();

    printf("Completed %s\n", __func__);
}

/*
    M4 TEST START
*/

__attribute__((unused)) static void test_trigger_page_fault(void)
{
    int volatile *addr = (int *)0xfffffffffff0;  // last virtual address of user space
    *addr = 3;
    printf("%d\n", *addr);
}

__attribute__((unused)) static void test_reserve_vspace_region(void)
{
    printf("Access 256MB buffer in the middle.\n");
    printf("heap size 0x%lx\n", VHEAP_SIZE);
    size_t bytes = (size_t)1 << 36;  // 1 TB
    size_t len = bytes / sizeof(size_t);
    size_t *large_arry = malloc(bytes);
    assert(large_arry);
    printf("Allocated array on the heap starting at %p with size 0x%lx bytes\n",
           large_arry, bytes);
    printf("Accessing at the beginning.\n");
    large_arry[0] = 42;
    assert(large_arry[0] == 42);
    printf("Accessing in the middle.\n");
    large_arry[len / 2] = 69;
    assert(large_arry[len / 2] == 69);
    printf("Accessing at the end.\n");
    large_arry[len - 1] = 420;
    assert(large_arry[len - 1] == 420);

    printf("Freeing the memory.\n");
    // free(large_arry);

    printf("buffer is at %p\n", large_arry);
    printf("before\n");
    mm_tracker_debug_print(&get_current_paging_state()->vheap_tracker);

    paging_unmap(get_current_paging_state(), (char *)large_arry - 0x20);
    printf("after\n");
    mm_tracker_debug_print(&get_current_paging_state()->vheap_tracker);

    printf("done with reserve vspace region\n");
}

__attribute__((unused)) static void test_morecore_free(void)
{
    lesscore();
}


__attribute__((unused)) static void test_page_fault_in_spawnee(void)
{
    errval_t err;

    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    err = start_process("selfpaging", si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn selfpaging");
    }
    assert(err_is_ok(err));
}

__attribute__((unused)) static void test_page_fault_already_handled(void)
{
    errval_t err;

    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    err = start_process("selfpaging_already_handled", si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn selfpaging_handled");
    }
    assert(err_is_ok(err));
}

void run_m4_tests(void)
{
    // test_trigger_page_fault();
    test_reserve_vspace_region();
    test_page_fault_in_spawnee();
    test_page_fault_already_handled();

    printf("Completed %s\n", __func__);
}


/*
    M5 TEST START
*/

__attribute__((unused)) static void test_ump_spawn(void)
{
    errval_t err = aos_ump_send(&aos_ump_server_chans[1], AosRpcSpawnRequest, "memeater",
                                strlen("memeater"));
    assert(err_is_ok(err));

    // get response!
    aos_rpc_msg_type_t type;
    char *payload;
    size_t len;
    err = aos_ump_receive(&aos_ump_server_chans[1], &type, &payload, &len);
    assert(err_is_ok(err));
    assert(type == AosRpcSpawnResponse);
    DEBUG_PRINTF("launched process; PID is: 0x%lx\n", *(size_t *)payload);
}

__attribute__((unused)) static void test_boot_all_cores(void)
{
    errval_t err;

    // core 1 is booted by default
    // err = boot_core(1);
    // if (err_is_fail(err)) {
    //     DEBUG_ERR(err, "failed to boot core");
    // }
    // assert(err_is_ok(err));

    err = boot_core(2);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }
    assert(err_is_ok(err));

    err = boot_core(3);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to boot core");
    }
    assert(err_is_ok(err));
}

__attribute__((unused)) static void test_cpu_off_on(void)
{
    errval_t err;

    delayus_t micro_sec = 1;
    delayus_t sec = 1000 * 1000 * micro_sec;

    // spawn infinite_print on core 1
    err = aos_ump_send(&aos_ump_server_chans[1], AosRpcSpawnRequest, "infinite_print",
                       strlen("infinite_print"));
    assert(err_is_ok(err));

    // wait
    barrelfish_usleep(3 * sec);

    // turn core 1 off
    err = aos_ump_send(&aos_ump_server_chans[1], AosRpcCpuOff, "off", strlen("off"));
    assert(err_is_ok(err));

    // wait
    barrelfish_usleep(3 * sec);

    // turn core 1 on
    err = cpu_on(1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to turn cpu on");
    }
    assert(err_is_ok(err));
}

void run_m5_tests(void)
{
    switch (disp_get_current_core_id()) {
    case 0:
        // test_spawn_single_process();
        // test_spawn_memeater();

        // DEMO TESTS
        test_spawn_process("demom5");
        // test_boot_all_cores();
        //  test_cpu_off_on();
        break;
    case 1:
        // test_spawn_single_process();
        // test_spawn_single_process();
        break;
    case 2:
        break;
    case 3:
        break;
    default:
        break;
    }
    DEBUG_PRINTF("Completed %s\n", __func__);
}

/*
    M6 TEST START
*/

__attribute__((unused)) static void test_large_ping_pong(void)
{
    errval_t err;
    struct aos_ump *ump;

    ump = &aos_ump_server_chans[1];

    char *ping = "ping";
    char *payload = (char *)malloc(AOS_UMP_MSG_MAX_BYTES);
    for (int i = 0; i < AOS_UMP_MSG_MAX_BYTES; i += strlen(ping)) {
        memcpy(payload + i, ping, strlen(ping));
    }

    // give the core some to time to boot
    barrelfish_usleep(1000 * 1000);
    err = aos_ump_send(ump, AosRpcPing, payload, strlen(payload));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
    }
    assert(err_is_ok(err));
}

void run_m6_tests(void)
{
    switch (disp_get_current_core_id()) {
    case 0:
        // test_large_ping_pong();
        DEBUG_PRINTF("spawning demom6\n");
        test_spawn_process("demom6");
        break;
    case 1:
        break;
    case 2:
        break;
    case 3:
        break;
    default:
        break;
    }
    DEBUG_PRINTF("Completed %s\n", __func__);
}

void run_tests(void)
{
    run_m6_tests();
}
