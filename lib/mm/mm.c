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

    // init slab allocator
    slab_init(&mm->slabs, sizeof(mmnode_t), slab_refill_func);

    // init slot allocator
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;

    // init datastructure
    mm->head = NULL;
    mm->tail = NULL;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    mmnode_t *curr = mm->head;
    mmnode_t *prev = NULL;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        slab_free(&mm->slabs, prev);
    }
    mm->head = NULL;
    mm->tail = NULL;
}

// helper functions start

static void node_insert_last(struct mm *mm, mmnode_t *node)
{
    if (mm->head == NULL) {
        mm->head = node;
    } else {
        mm->tail->next = node;
        node->prev = mm->tail;
    }

    mm->tail = node;
}

static errval_t node_split(struct mm *mm, mmnode_t *node, size_t offset,
                           mmnode_t **left_split, mmnode_t **right_split)
{
    mmnode_t *new_node = slab_alloc(&mm->slabs);
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
    if (node == mm->tail) {
        new_node->next = NULL;
        mm->tail = new_node;
    } else {
        new_node->next = node->next;
        node->next->prev = new_node;
    }
    new_node->prev = node;
    node->next = new_node;

    return SYS_ERR_OK;
}

static errval_t mm_refill_slabs(struct mm *mm)
{
    size_t free = slab_freecount(&mm->slabs);
    if (free < 8) {
        return slab_default_refill(&mm->slabs);
    }
    return SYS_ERR_OK;
}

static void mm_print(struct mm *mm)
{
    printf("===\n");
    printf("Current state:\n");
    mmnode_t *curr = mm->head;
    if (mm->head == NULL) {
        printf("none");
        printf("\n\n");
        return;
    }
    while (curr != NULL) {
        if (curr->type == NodeType_Allocated) {
            printf("Allocated: (%lu, %lu)\n", curr->base, curr->base + curr->size - 1);
        } else if (curr->type == NodeType_Free) {
            printf("Free: (%lu, %lu)\n", curr->base, curr->base + curr->size - 1);
        } else {
            printf("Type unknowne\n");
        }
        curr = curr->next;
    }
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

    mmnode_t *new_node = slab_alloc(&mm->slabs);
    new_node->type = NodeType_Free;
    new_node->base = memory_base;
    new_node->size = memory_size;
    new_node->capinfo = (struct capinfo) {
        .cap = cap,
        .base = memory_base,
        .size = memory_size,
    };
    node_insert_last(mm, new_node);

    debug_printf("Memory added: (%lu,%lu)\n", memory_base, memory_base + memory_size - 1);
    mm_print(mm);

    return SYS_ERR_OK;
}

static errval_t mm_allocate_slot(struct mm *mm, struct capref *cap)
{
    errval_t err;
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, cap);
    if (err_is_fail(err)) {
        if (mm->slot_refill == NULL) {
            return err_push(err, MM_ERR_SLOT_NOSLOTS);
        }

        err = mm->slot_refill(mm->slot_alloc_inst);
        if (err_is_fail(err)) {
            return err_push(err, MM_ERR_SLOT_NOSLOTS);
        }

        err = mm->slot_alloc(mm->slot_alloc_inst, 1, cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Allocating slot");
            return err_push(err, MM_ERR_SLOT_NOSLOTS);
        }
    }

    return err;
}

/*
 * there are cases where a memory region needs to be aligned to a certain boundary i.e.
 * has to START at a memory address that is a multiple of the alignment
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t requested_size, size_t alignment,
                          struct capref *retcap)
{
    debug_printf("Memory allocation request of %lu KB aligned to %lu KB\n",
                 requested_size / 1024, alignment / 1024);

    errval_t err;
    if (requested_size < MIN_ALLOC || MAX_ALLOC < requested_size) {
        debug_printf("Memory allocation denied: Out of bounds");
        return LIB_ERR_RAM_ALLOC_WRONG_SIZE;
    }

    err = mm_allocate_slot(mm, retcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not allocate slot for retcap\n");
        return err;
    }

    mmnode_t *curr = mm->head;  // TODO do next fit instead of first fit
    while (curr != NULL) {
        // space left in node
        if (curr->type == NodeType_Allocated || curr->size < requested_size) {
            curr = curr->next;
            continue;
        }

        // memory base address is not aligned
        if (curr->base % alignment != 0) {
            size_t offset = alignment - (curr->base % alignment);
            if (curr->size - offset < requested_size) {
                curr = curr->next;
                continue;
            }
            // create an aligned node
            mmnode_t *left_split, *right_split;
            err = node_split(mm, curr, offset, &left_split, &right_split);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to split mmnodes");
                return err;
            }
            curr = right_split;
        }

        err = cap_retype(*retcap, curr->capinfo.cap, curr->base - curr->capinfo.base,
                         mm->objtype, requested_size, 1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "could not retype region cap");
            return err;
        }

        // exact fit
        if (curr->size == requested_size) {
            curr->type = NodeType_Allocated;
            break;
        }

        // split a node
        mmnode_t *left_split, *right_split;
        err = node_split(mm, curr, requested_size, &left_split, &right_split);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes");
            return err;
        }
        left_split->type = NodeType_Allocated;
        right_split->type = NodeType_Free;

        // refill slabs as we use slabs in node_split
        mm_refill_slabs(mm);
        break;
    }

    debug_printf("Memory allocated: (%lu, %lu)\n", curr->base,
                 curr->base + curr->size - 1);

    mm_print(mm);
    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

static errval_t mm_merge(struct mm *mm, mmnode_t *left_split)
{
    if (left_split == NULL) {
        return LIB_ERR_RAM_ALLOC;
    }

    mmnode_t *right_split = left_split->next;
    if (right_split == NULL) {
        return LIB_ERR_RAM_ALLOC;
    }

    if (!capcmp(left_split->capinfo.cap, right_split->capinfo.cap)) {
        return LIB_ERR_RAM_ALLOC;
    }

    if (left_split->type == NodeType_Free && right_split->type == NodeType_Free) {
        assert(left_split->base + left_split->size == right_split->base);

        debug_printf("Coalescing blocks at: %lu and %lu\n", left_split->base,
                     right_split->base);

        left_split->size += right_split->size;
        left_split->next = right_split->next;

        if (right_split->next != NULL) {
            right_split->next->prev = left_split;
        }

        slab_free(&mm->slabs, right_split);
        return SYS_ERR_OK;
    }
    return LIB_ERR_RAM_ALLOC;
}

errval_t mm_free(struct mm *mm, struct capref cap)
{
    errval_t err;

    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get the frame info\n");
    }

    size_t memory_base = c.u.ram.base;
    size_t memory_size = c.u.ram.bytes;
    debug_printf("Memory free request for address %lu\n", memory_base);

    mmnode_t *curr = mm->head;
    while (curr != NULL) {
        if (curr->base != memory_base || curr->size != memory_size) {
            curr = curr->next;
            continue;
        }

        err = cap_destroy(cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to destroy the ram cap");
            return err;
        }
        curr->type = NodeType_Free;
        mm_merge(mm, curr);
        mm_merge(mm, curr->prev);

        printf("Memory freed: (%lu, %lu)\n", memory_base, memory_base + memory_size - 1);
        return SYS_ERR_OK;
    }
    // Invalid reference, as this was never allocated
    printf("Invalid memory free request: (%lu, %lu)\n", memory_base, memory_size);
    return LIB_ERR_RAM_ALLOC;
}
