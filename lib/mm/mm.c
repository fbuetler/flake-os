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


/**
 * @brief initiales the memory manager
 *
 * @param mm the memory manager
 * @param objtype the object type that this memory manager allocates
 * @param slab_refill_func the functio to refill the slab allocator
 * @param slot_alloc_func the function to allocate a slot
 * @param slot_refill_func the function to refill the slot allocator
 * @param slot_allocator the slot allocator
 * @return errval_t
 */
errval_t mm_init(struct mm *mm, enum objtype objtype, slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func, slot_refill_t slot_refill_func,
                 void *slot_allocator)
{
    mm->objtype = objtype;

    mm_tracker_init(&mm->mmt, &mm->slab_allocator);

    // init slot allocator
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_allocator = slot_allocator;

    return SYS_ERR_OK;
}


/**
 * @brief adds the provided capability to the memory allocator datastructure
 *
 * @param mm the memory manager
 * @param cap the capability that represent the added memory region
 * @return errval_t
 *
 * a node is created for each capability
 */
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

    mmnode_t *new_node;

    err = mm_tracker_alloc(&mm->mmt, &new_node);
    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_ALLOC_NODE);
    }

    new_node->type = NodeType_Free;
    new_node->base = memory_base;
    new_node->size = memory_size;
    new_node->capinfo = (struct capinfo) {
        .cap = cap,
        .base = memory_base,
        .size = memory_size,
    };
    mm_tracker_node_insert(&mm->mmt, new_node);

    debug_printf("Memory added: (%lu,%lu)\n", memory_base, memory_base + memory_size - 1);

    return SYS_ERR_OK;
}


/**
 * @brief allocate a memory region
 *
 * @param mm the memory manager
 * @param requested_size size that has to be allocated
 * @param alignment the allocated memory has to START at a multiple of this alignment
 * @param retcap the capability that represents the allocated memory region
 * @return errval_t
 *
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

    errval_t err = SYS_ERR_OK;

    assert(mm->mmt.head);

    mm->slot_refill(mm->slot_allocator);
    err = mm_tracker_refill(&mm->mmt);
    if (err_is_fail(err)) {
        return err;
    }

    err = mm->slot_alloc(mm->slot_allocator, 1, retcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not allocate slot for retcap\n");
        return err_push(err, MM_ERR_SLOT_NOSLOTS);
    }

    mmnode_t *next_fit_node;
    err = mm_tracker_get_next_fit(&mm->mmt, &next_fit_node, requested_size, alignment);
    if (err_is_fail(err)) {
        debug_printf("Memory allocation failed: memory exhausted\n");
        mm_tracker_debug_print(&mm->mmt);
        return err_push(err, MM_ERR_FIND_NODE);
    }

    // create an aligned node
    size_t offset = (next_fit_node->base % alignment) > 0
                        ? alignment - (next_fit_node->base % alignment)
                        : 0;
    mmnode_t *offset_split_left, *offset_split_right;
    mmnode_t *leftover_split_left, *leftover_split_right;

    if (offset > 0) {
        err = mm_tracker_node_split(&mm->mmt, next_fit_node, offset, &offset_split_left,
                                    &offset_split_right);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes for alignment");
            return err_push(err, MM_ERR_SPLIT_NODE);
        }

        offset_split_left->type = NodeType_Free;

        next_fit_node = offset_split_right;
    }

    if (next_fit_node->size > requested_size) {
        // split a node
        err = mm_tracker_node_split(&mm->mmt, next_fit_node, requested_size,
                                    &leftover_split_left, &leftover_split_right);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to split mmnodes");
            err = err_push(err, MM_ERR_SPLIT_NODE);
            goto unwind_first_split;
        }
        leftover_split_right->type = NodeType_Free;
        next_fit_node = leftover_split_left;
    }

    next_fit_node->type = NodeType_Allocated;

    err = cap_retype(*retcap, next_fit_node->capinfo.cap,
                     next_fit_node->base - next_fit_node->capinfo.base, mm->objtype,
                     requested_size, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not retype region cap");
        printf("base address: %p\n", next_fit_node->base);
        mm_tracker_debug_print(&mm->mmt);
        err = err_push(err, LIB_ERR_CAP_RETYPE);
        goto unwind_second_split;
    }

    mm->mmt.head = next_fit_node;
    debug_printf("Memory allocated: (%p, %lu)\n", next_fit_node->base,
                 next_fit_node->base + next_fit_node->size - 1);
    // mm_tracker_debug_print(&mm->mmt);
    return SYS_ERR_OK;

unwind_second_split:
    mm_tracker_node_merge(&mm->mmt, offset_split_left);
unwind_first_split:
    mm_tracker_node_merge(&mm->mmt, leftover_split_left);
    return err;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

/**
 * @brief splits the node into multiple nodes, one of them represent the freed memory
 *
 * @param node pointer to the node that represent the partially freed memory region and on
 * return will point to the node that represent the freed memory region
 * @param memory_base * memory base address of the freed memory region
 * @param memory_size memory size of the  freed memory region
 * @return errval_t
 *
 */
/*
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
*/

/**
 * @brief frees an allocated memory region
 *
 * @param mm the memory manager
 * @param cap the capability that represent the freed memory region
 * @return errval_t
 *
 * partial free have to respect that the size needs to be aligned to the BASE_PAGE_SIZE
 */
errval_t mm_free(struct mm *mm, struct capref cap)
{
    errval_t err;

    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get the frame info\n");
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    size_t memory_base = c.u.ram.base;
    size_t memory_size = c.u.ram.bytes;

    err = mm_tracker_free(&mm->mmt, memory_base, memory_size);
    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_MM_FREE);
    }

    err = cap_destroy(cap);
    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_MM_FREE);
    }

    debug_printf("Memory freed: (%lu, %lu)\n", memory_base, memory_base + memory_size - 1);

    return SYS_ERR_OK;
}
