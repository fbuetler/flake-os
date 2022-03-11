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
    mm->objtype = objtype;

    // sizes of different types:
    // list_t: 24
    // map_t: 24
    // region_t: 24
    // list_node_t: 24
    // map_node_t: 32
    // capref: 16
    // size_t: 8
    size_t blocksize = 32;
    // init slab allocator
    slab_init(&mm->slabs, blocksize, slab_refill_func);

    // init slot allocator
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;

    // init datastructure
    for (int i = 0; i < BUCKET_COUNT; i++) {
        mm->free_buckets[i] = malloc(sizeof(list_t));
        list_init(mm->free_buckets[i]);
    }
    for (int i = 0; i < BUCKET_COUNT; i++) {
        mm->existing_buckets[i] = malloc(sizeof(map_t));
        map_init(mm->existing_buckets[i]);
    }
    mm->allocations = malloc(sizeof(map_t));
    map_init(mm->allocations);

    mm->added = false;  // TODO FIXME: handle multiple regions

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    for (int i = 0; i < BUCKET_COUNT; i++) {
        list_destroy(mm->free_buckets[i]);
    }
    for (int i = 0; i < BUCKET_COUNT; i++) {
        map_destroy(mm->existing_buckets[i]);
    }
    map_destroy(mm->allocations);
    free(mm->free_buckets);
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
        list_print(mm->free_buckets[i]);
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
    size_t memory_base_addr = c.u.ram.base;
    // TODO FIXME: we throw some memory away here
    size_t memory_size = next_lower_power_of_two(c.u.ram.bytes);
    printf("Wasted %lu KB of memory\n", (c.u.ram.bytes - memory_size) / 1024);

    size_t bucket_index = get_bucket_index(memory_size);
    region_t *region = malloc(sizeof(region_t));
    region->lower = memory_base_addr;
    region->upper = memory_base_addr + memory_size - 1;
    region->cap = &cap;  // TODO is this dangerous?
    list_insert_last(mm->free_buckets[bucket_index], region);
    map_put(mm->existing_buckets[bucket_index], memory_base_addr, region);

    mm->base_addr = memory_base_addr;

    debug_printf("Memory added: (%lu,%lu)\n", region->lower, region->upper);

    mm_print(mm);
    mm->added = true;  // TODO FIXME: handle multiple regions

    return SYS_ERR_OK;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                          struct capref *retcap)
{
    // no matter what the size has to be a power of 2
    if (size < MIN_ALLOC || MAX_ALLOC < size) {
        // requested size is too small or too big
        // TODO should we allow smaller sizes
        return LIB_ERR_RAM_ALLOC_WRONG_SIZE;
    } else if (size % BASE_PAGE_SIZE != 0) {
        // requested size is not aligned
        // TODO should we allow unaligned sizes
        return LIB_ERR_RAM_ALLOC_WRONG_SIZE;
    }

    size_t bucket_index = get_bucket_index(size);
    region_t *runner = NULL;

    // there is already such a block
    if (mm->free_buckets[bucket_index]->size > 0) {
        runner = list_remove_first(mm->free_buckets[bucket_index]);
        if (runner == NULL) {
            debug_printf("there should be a block but isnt\n");
            return LIB_ERR_RAM_ALLOC;
        }

        size_t *allocated_size = malloc(sizeof(size_t));
        *allocated_size = runner->upper - runner->lower + 1;
        map_put(mm->allocations, runner->lower, allocated_size);
        // TODO fill in retcap
        // TODO use cap_retype

        debug_printf("Memory allocated: (%lu, %lu)\nWasted memory: %lu KB\n",
                     runner->lower, runner->upper, *allocated_size / 1024);
        return SYS_ERR_OK;
    }

    // search for the next larger block
    int i;
    for (i = bucket_index + 1; i < BUCKET_COUNT; i++) {
        if (mm->free_buckets[i]->size > 0) {
            // found a larger block
            break;
        }
    }

    // memory is exhausted
    if (i == BUCKET_COUNT) {
        debug_printf("Failed to allocate memory\n");
        return LIB_ERR_RAM_ALLOC_FIXED_EXHAUSTED;
    }

    // remove a block
    runner = list_remove_first(mm->free_buckets[i]);
    if (runner == NULL) {
        debug_printf("There should be a block but isnt\n");
        return LIB_ERR_RAM_ALLOC;
    }
    i--;

    // split the block until it fits our need
    for (; i >= bucket_index; i--) {
        // divide the block in two halfs
        // TODO use cap_retype
        region_t *left_split = malloc(sizeof(region_t));
        left_split->lower = runner->lower;
        left_split->upper = runner->lower + (runner->upper - runner->lower) / 2;

        region_t *right_split = malloc(sizeof(region_t));
        right_split->lower = runner->lower + (runner->upper - runner->lower + 1) / 2;
        right_split->upper = runner->upper;

        // add both halfs to the free list
        list_insert_last(mm->free_buckets[i], left_split);
        list_insert_last(mm->free_buckets[i], right_split);
        map_put(mm->existing_buckets[i], left_split->lower, left_split);
        map_put(mm->existing_buckets[i], right_split->lower, right_split);

        // remove a block and continue the downward pass
        runner = list_remove_first(mm->free_buckets[i]);
        if (runner == NULL) {
            debug_printf("There should be a block but isnt\n");
            return LIB_ERR_RAM_ALLOC;
        }
    }

    size_t *allocated_size = malloc(sizeof(size_t));
    *allocated_size = runner->upper - runner->lower + 1;
    map_put(mm->allocations, runner->lower, allocated_size);
    // TODO fill in retcap
    // TODO use cap_retype

    debug_printf("Memory allocated: (%lu, %lu)\nWasted memory: %lu KB\n", runner->lower,
                 runner->upper, *allocated_size / 1024);

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

static errval_t mm_merge_buddies(struct mm *mm, size_t start_addr, int bucket_index)
{
    if (bucket_index + 1 == BUCKET_COUNT) {
        // reached top bucket
        return SYS_ERR_OK;
    }

    // calculate buddy number and buddy address
    size_t block_size = 1 << bucket_index;
    size_t buddy_address;
    size_t buddy_number = (start_addr - mm->base_addr) / block_size;
    if (buddy_number % 2 == 0) {
        buddy_address = start_addr + (1 << bucket_index);
    } else {
        buddy_address = start_addr - (1 << bucket_index);
    }

    // search the buddy in the free list
    bool buddy_found = false;
    for (int i = 0; i < mm->free_buckets[bucket_index]->size; i++) {
        region_t *buddy = list_get_index(mm->free_buckets[bucket_index], i);
        if (buddy == NULL) {
            // nothing found at index (this should not happen)
            continue;
        }
        if (buddy->lower != buddy_address) {
            // not our buddy
            continue;
        }
        // the buddy is also free
        buddy_found = true;
        size_t parent_address;
        if (buddy_number % 2 == 0) {
            // buddy is the block after the freed one
            parent_address = start_addr;
            printf("Coalescing blocks in bucket %lu at: %lu and %lu\n", bucket_index,
                   start_addr, buddy_address);
        } else {
            // buddy is the block before the freed one
            parent_address = buddy_address;
            printf("Coalescing blocks in bucket %lu at: %lu and %lu\n", bucket_index,
                   buddy_address, start_addr);
        }
        // add merged parent to free lsit
        region_t *parent = map_get(mm->existing_buckets[bucket_index + 1], parent_address);
        list_insert_last(mm->free_buckets[bucket_index + 1], parent);

        // remove coalesced buddies from free list
        list_remove_index(mm->free_buckets[bucket_index], i);
        list_remove_index(mm->free_buckets[bucket_index],
                          mm->free_buckets[bucket_index]->size - 1);

        // release not anymore use subregions
        free(map_remove(mm->existing_buckets[bucket_index], start_addr));
        free(map_remove(mm->existing_buckets[bucket_index], buddy_address));

        break;
    }
    // remove allocation
    map_remove(mm->allocations, start_addr);

    if (!buddy_found) {
        return 0;
    }

    // TODO make iterative
    if (buddy_number % 2 == 0) {
        return mm_merge_buddies(mm, start_addr, bucket_index + 1);
    } else {
        return mm_merge_buddies(mm, buddy_address, bucket_index + 1);
    }
}

errval_t mm_free(struct mm *mm, struct capref cap)
{
    errval_t err;

    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get the frame info\n");
    }

    size_t start_addr = c.u.ram.base;

    size_t *size = map_get(mm->allocations, start_addr);
    // Invalid reference, as this was never allocated
    if (size == NULL) {
        printf("Invalid free request\n");
        return 1;
    }

    size_t bucket_index = get_bucket_index(*size);
    region_t *region = map_get(mm->existing_buckets[bucket_index], start_addr);

    // add the freed block to the free list
    list_insert_last(mm->free_buckets[bucket_index], region);
    printf("Memory freed: (%lu, %lu)\n", region->lower, region->upper);

    return mm_merge_buddies(mm, start_addr, bucket_index);
}
