/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

/*
 * Copyright (c) 2008, 2011, ETH Zurich.
 * Copyright (c), 2022, The University of British Columbia
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>


errval_t mm_init(struct mm *mm, enum objtype objtype, slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func, slot_refill_t slot_refill_func,
                 void *slot_alloc_inst)
{
    errval_t err = 0;

    // (depends on init_buffer_size in mem_alloc.c)
    size_t blocksize = 256;  // TODO bigger? smaller?
    slab_init(&(mm->slabs), blocksize, slab_refill_func);
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->objtype = objtype;

    // init datastructure
    for (int i = 0; i < BUCKET_COUNT; i++) {
        mm->buckets[i] = malloc(sizeof(list_t));
        list_init(mm->buckets[i]);
    }
    mm->allocations = malloc(sizeof(map_t));
    map_init(mm->allocations);

    mm->added = false;  // TODO FIXME: handle multiple regions

    return err;
}

void mm_destroy(struct mm *mm)
{
    for (int i = 0; i < BUCKET_COUNT; i++) {
        list_destroy(mm->buckets[i]);
    }
    free(mm->buckets);
    map_destroy(mm->allocations);
    free(mm->allocations);
}

// helper functions start

static int get_bucket_index(size_t size)
{
    size = size >> MIN_ALLOC_LOG2;
    int bucket_index = 0;
    for (; bucket_index < BUCKET_COUNT; bucket_index++) {
        if (size & 1) {
            break;
        }
        size = size >> 1;
    }
    return bucket_index;
}

static size_t next_lower_power_of_two(size_t n)
{
    size_t i = 0;
    while (1 << i <= n) {
        i++;
    }

    return 1 << (i - 1);
}

static void mm_print(struct mm *mm)
{
    printf("\nCurrent state:\n");
    printf("Free memory lists:\n");
    for (int i = 0; i < BUCKET_COUNT; i++) {
        printf("%i: ", i + MIN_ALLOC_LOG2);
        list_print(mm->buckets[i]);
        printf("\n");
    }
    printf("Allocated memory regions:\n");
    map_print(mm->allocations);
    printf("\n\n");
}

// helper functions end

errval_t mm_add(struct mm *mm, struct capref cap)
{
    errval_t err;

    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get the frame info\n");
    }
    debug_printf("Size of memory chunk %" PRIu64 " KB\n", c.u.ram.bytes / 1024);

    if (mm->added) {
        return LIB_ERR_RAM_ALLOC;  // TODO FIXME: handle multiple regions
    }

    // add memory as free memory to datastructure
    genpaddr_t memory_base_addr = c.u.ram.base;
    // TODO FIXME: we throw some memory away here
    size_t memory_size = next_lower_power_of_two(c.u.ram.bytes);
    printf("Wasted %lu KB of memory\n", (c.u.ram.bytes - memory_size) / 1024);

    size_t bucket_index = get_bucket_index(memory_size);
    region_t *region = malloc(sizeof(region_t));
    region->lower = memory_base_addr;
    region->upper = memory_base_addr + memory_size - 1;
    list_insert_last(mm->buckets[bucket_index], region);

    mm->base_addr = memory_base_addr;

    debug_printf("Memory added: (%lu,%lu)\n", region->lower, region->upper);

    mm_print(mm);
    mm->added = true;  // TODO FIXME: handle multiple regions

    return SYS_ERR_OK;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                          struct capref *retcap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}
