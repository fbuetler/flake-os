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

// helper functions start

static void node_insert(struct mm *mm, mmnode_t *node)
{
    if (mm->head == NULL) {
        mm->head = node;
    } else {
        mmnode_t *tail = mm->head->prev;
        tail->next = node;
        node->prev = tail;
    }
    node->next = mm->head;
    mm->head->prev = node;
}

static errval_t node_split(struct mm *mm, mmnode_t *node, size_t offset,
                           mmnode_t **left_split, mmnode_t **right_split)
{
    mmnode_t *new_node = slab_alloc(&mm->slab_allocator);
    if (new_node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    *left_split = node;
    *right_split = new_node;

    // adjust sizes
    new_node->base = node->base + offset;
    new_node->size = node->size - offset;
    new_node->capinfo = node->capinfo;

    node->size = offset;

    // relink nodes
    new_node->next = node->next;
    node->next->prev = new_node;
    node->next = new_node;
    new_node->prev = node;

    return SYS_ERR_OK;
}

static errval_t node_merge(struct mm *mm, mmnode_t *left_split)
{
    if (left_split == NULL) {
        return LIB_ERR_RAM_ALLOC;
    }

    mmnode_t *right_split = left_split->next;
    if (right_split == NULL) {
        return LIB_ERR_RAM_ALLOC;
    }

    // we migh have a circular buffer but the memory is still linear
    if (left_split->base > right_split->base) {
        return SYS_ERR_OK;
    }

    if (!capcmp(left_split->capinfo.cap, right_split->capinfo.cap)) {
        return SYS_ERR_OK;
    }

    if (left_split->type == NodeType_Free && right_split->type == NodeType_Free) {
        assert(left_split->base + left_split->size == right_split->base);

        debug_printf("Coalescing blocks at: %lu and %lu\n", left_split->base,
                     right_split->base);

        // resize left split
        left_split->size += right_split->size;

        // relink nodes
        if (mm->head == right_split) {
            mm->head = right_split->next;
        }
        left_split->next = right_split->next;
        right_split->next->prev = left_split;

        slab_free(&mm->slab_allocator, right_split);
        return SYS_ERR_OK;
    }
    return SYS_ERR_OK;
}


errval_t mm_init(struct mm *mm, enum objtype objtype, slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func, slot_refill_t slot_refill_func,
                 void *slot_allocator)
{
    mm->objtype = objtype;

    // init slab allocator
    slab_init(&mm->slab_allocator, sizeof(mmnode_t), slab_refill_func);

    // init slot allocator
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_allocator = slot_allocator;

    // init datastructure
    mm->head = NULL;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    if (mm->head == NULL) {
        return;
    }

    mmnode_t *curr = mm->head->next;
    while (curr != mm->head) {
        mmnode_t *prev = curr;
        curr = curr->next;
        free(prev);
    }
    free(mm->head);
    mm->head = NULL;
}

void mm_debug_print(struct mm *mm)
{
    printf("===\n");
    printf("Current state:\n");
    if (mm->head == NULL) {
        printf("none");
        printf("\n\n");
        return;
    }
    printf("Head at %lu\n", mm->head->base);
    mmnode_t *curr = mm->head;
    do {
        if (curr->type == NodeType_Allocated) {
            printf("Allocated: (%lu, %lu)\n", curr->base, curr->base + curr->size - 1);
        } else if (curr->type == NodeType_Free) {
            printf("Free: (%lu, %lu)\n", curr->base, curr->base + curr->size - 1);
        } else {
            printf("Type unknown\n");
        }
        curr = curr->next;
    } while (curr != mm->head);
    printf("===\n");
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

    size_t memory_base = c.u.ram.base;
    size_t memory_size = c.u.ram.bytes;

    mmnode_t *new_node = slab_alloc(&mm->slab_allocator);
    new_node->type = NodeType_Free;
    new_node->base = memory_base;
    new_node->size = memory_size;
    new_node->capinfo = (struct capinfo) {
        .cap = cap,
        .base = memory_base,
        .size = memory_size,
    };
    node_insert(mm, new_node);

    debug_printf("Memory added: (%lu,%lu)\n", memory_base, memory_base + memory_size - 1);
    // mm_debug_print(mm);

    return SYS_ERR_OK;
}


/*
 * make sure the requested_size size is aligned to 4KB
 *
 * there are cases where a memory region needs to be aligned to a certain boundary i.e.
 * has to START at a memory address that is a multiple of the alignment
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t requested_size, size_t alignment,
                          struct capref *retcap)
{
    debug_printf("Memory allocation request of %lu aligned to %lu\n", requested_size,
                 alignment);

    errval_t err;
    if (requested_size < MIN_ALLOC || MAX_ALLOC < requested_size) {
        debug_printf("Memory allocation denied: Out of bounds");
        return LIB_ERR_RAM_ALLOC_WRONG_SIZE;
    }

    if (alignment == 0) {
        // use sane default
        alignment = 1;
    }

    if (mm->head == NULL) {
        debug_printf("Memory allocation not possible: no memory initialized\n");
        return LIB_ERR_RAM_ALLOC;
    }

    err = mm->slot_alloc(mm->slot_allocator, 1, retcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not allocate slot for retcap\n");
        return err_push(err, MM_ERR_SLOT_NOSLOTS);
    }

    mmnode_t *curr = mm->head;
    do {
        // space left in node
        if (curr->type == NodeType_Allocated || curr->size < requested_size) {
            curr = curr->next;
            continue;
        }

        // memory base address is not aligned
        if (curr->base % alignment != 0) {
            size_t offset = alignment - (curr->base % alignment);
            if (0 < curr->size - offset || curr->size - offset < requested_size) {
                curr = curr->next;
                continue;
            }
            // create an aligned node
            mmnode_t *left_split, *right_split;
            err = node_split(mm, curr, offset, &left_split, &right_split);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to split mmnodes for alignment");
                return err;
            }
            left_split->type = NodeType_Free;
            curr = right_split;
        }

        err = cap_retype(*retcap, curr->capinfo.cap, curr->base - curr->capinfo.base,
                         mm->objtype, requested_size, 1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "could not retype region cap");
            printf("base address: %lu\n", curr->base);
            mm_debug_print(mm);
            return err;
        }

        if (curr->size > requested_size) {
            // split a node
            mmnode_t *left_split, *right_split;
            err = node_split(mm, curr, requested_size, &left_split, &right_split);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to split mmnodes");
                return err;
            }
            right_split->type = NodeType_Free;
            curr = left_split;
        }
        curr->type = NodeType_Allocated;

        mm->head = curr;

        if (slab_freecount(&mm->slab_allocator) < 8) {
            // TODO maybe set this function as slabs->refill_func
            err = slab_default_refill(&mm->slab_allocator);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to refill slab allocator");
                return LIB_ERR_SLAB_REFILL;
            }
        }

        debug_printf("Memory allocated: (%lu, %lu)\n", curr->base,
                     curr->base + curr->size - 1);
        // mm_debug_print(mm);
        return SYS_ERR_OK;
    } while (curr != mm->head);

    debug_printf("Memory allocation failed: memory exhausted\n");
    mm_debug_print(mm);
    return LIB_ERR_RAM_ALLOC_FIXED_EXHAUSTED;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

static errval_t mm_partial_free(struct mm *mm, mmnode_t **node, size_t memory_base,
                                size_t memory_size)
{
    errval_t err;

    if ((*node)->base == memory_base) {
        debug_printf("Partial memory free request: left aligned\n");
        size_t offset = memory_size;
        mmnode_t *left_split, *right_split;
        err = node_split(mm, *node, offset, &left_split, &right_split);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes in a left aligned partial "
                           "free");
            return err;
        }
        left_split->type = NodeType_Free;
        right_split->type = NodeType_Allocated;
        *node = left_split;
    } else if ((*node)->base + (*node)->size - memory_size == memory_base) {
        debug_printf("Partial memory free request: right aligned\n");
        size_t offset = memory_base - (*node)->base;
        mmnode_t *left_split, *right_split;
        err = node_split(mm, *node, offset, &left_split, &right_split);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes in a right aligned partial "
                           "free");
            return err;
        }
        left_split->type = NodeType_Allocated;
        right_split->type = NodeType_Free;
        *node = right_split;
    } else {
        debug_printf("Partial memory free request: middle aligned\n");
        size_t left_offset = memory_base - (*node)->base;
        size_t right_offset = memory_base + memory_size - (*node)->base - left_offset;
        mmnode_t *left_split, *middle_split, *right_split;
        err = node_split(mm, *node, left_offset, &left_split, &middle_split);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes in a middle aligned partial "
                           "free");
            return err;
        }
        *node = middle_split;
        err = node_split(mm, *node, right_offset, &middle_split, &right_split);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes in a middle aligned partial "
                           "free");
            return err;
        }

        left_split->type = NodeType_Allocated;
        middle_split->type = NodeType_Free;
        right_split->type = NodeType_Allocated;
        *node = middle_split;
    }

    return SYS_ERR_OK;
}

errval_t mm_free(struct mm *mm, struct capref cap)
{
    errval_t err;

    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get the frame info\n");
        return LIB_ERR_RAM_ALLOC;
    }

    size_t memory_base = c.u.ram.base;
    size_t memory_size = c.u.ram.bytes;
    debug_printf("Memory free request for address %lu\n", memory_base);

    if (mm->head == NULL) {
        debug_printf("Memory free not possible: no memory initialized\n");
        return LIB_ERR_RAM_ALLOC;
    }

    mmnode_t *curr = mm->head;
    do {
        if (memory_base < curr->base || curr->base + curr->size <= memory_base) {
            curr = curr->next;
            continue;
        }

        if (curr->size != memory_size) {
            if (memory_size % BASE_PAGE_SIZE != 0) {
                debug_printf("Memory partial free not possible: size is not aligned\n");
                return LIB_ERR_RAM_ALLOC;
            }
            err = mm_partial_free(mm, &curr, memory_base, memory_size);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to do partial free");
                return err;
            }
        }

        err = cap_destroy(cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to destroy the ram cap");
            return err;
        }
        curr->type = NodeType_Free;
        node_merge(mm, curr);
        node_merge(mm, curr->prev);

        debug_printf("Memory freed: (%lu, %lu)\n", memory_base,
                     memory_base + memory_size - 1);
        // mm_debug_print(mm);

        return SYS_ERR_OK;
    } while (curr != mm->head);
    mm->head = curr;

    // Invalid reference, as this was never allocated
    printf("Invalid memory free request: (%lu, %lu)\n", memory_base, memory_size);
    return LIB_ERR_RAM_ALLOC;
}
