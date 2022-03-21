/**
 * \file
 * \brief AOS paging helpers.
 */

/*
 * Copyright (c) 2012, 2013, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/except.h>
#include <aos/slab.h>
#include "threads_priv.h"

#include <stdio.h>
#include <string.h>

static struct paging_state current;


/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state *st, enum objtype type, struct capref *ret)
{
    errval_t err;
    err = st->slot_allocator->alloc(st->slot_allocator, ret);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "slot_alloc failed");
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "vnode_create failed");
        return err;
    }
    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}


/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging
 *        state of the calling process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging state
 *        of a child process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
    debug_printf("paging_init\n");
    // TODO (M2): Call paging_init_state for &current
    // TODO (M4): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.
    set_current_paging_state(&current);

    // store root page table L0
    current.root_page_table.cap = cap_vroot;

    // init slot allocator
    current.slot_allocator = get_default_slot_allocator();

    // init slab allocator
    slab_init(&current.slab_allocator, sizeof(struct page_table), NULL);
    static uint8_t pt_buf[SLAB_STATIC_SIZE(64, sizeof(struct page_table))];
    slab_grow(&current.slab_allocator, pt_buf, sizeof(pt_buf));

    return SYS_ERR_OK;
}


/**
 * @brief Initializes the paging functionality for the calling thread
 *
 * @param[in] t   the tread to initialize the paging state for.
 *
 * This function prepares the thread to handing its own page faults
 */
errval_t paging_init_onthread(struct thread *t)
{
    // TODO (M4):
    //   - setup exception handler for thread `t'.
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief Find a free region of virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * @param[in]  st          A pointer to the paging state to allocate from
 * @param[out] buf         Returns the free virtual address that was found.
 * @param[in]  bytes       The requested (minimum) size of the region to allocate
 * @param[in]  alignment   The address needs to be a multiple of 'alignment'.
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    /**
     * TODO(M2): Implement this function
     *   - Find a region of free virtual address space that is large enough to
     *     accomodate a buffer of size `bytes`.
     */
    *buf = NULL;

    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * \brief Finds a free virtual address and maps `bytes` of the supplied frame at that address
 *
 * @param[in]  st      the paging state to create the mapping in
 * @param[out] buf     returns the virtual address at which this frame has been mapped.
 * @param[in]  bytes   the number of bytes to map.
 * @param[in]  frame   the frame capability to be mapped
 * @param[in]  flags   The flags that are to be set for the newly mapped region,
 *                     see 'paging_flags_t' in paging_types.h .
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags)
{
    // TODO(M2):
    // - Find and allocate free region of virtual address space of at least bytes in size.
    // - Map the user provided frame at the free virtual address
    // - return the virtual address in the buf parameter
    //
    // Hint:
    //  - think about what mapping configurations are actually possible

    return LIB_ERR_NOT_IMPLEMENTED;
}


static errval_t paging_get_or_create_pt(struct paging_state *st,
                                        struct page_table *parent_pt,
                                        size_t parent_pt_index, enum objtype pt_type,
                                        struct page_table **pt)
{
    errval_t err;
    *pt = (parent_pt->entries)[parent_pt_index];
    if (*pt != NULL) {
        return SYS_ERR_OK;
    }

    // allocate page table
    struct capref pt_cap;
    // no need to allocate a slot as this is done in pt_alloc
    err = pt_alloc(st, pt_type, &pt_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate page table");
        return err;
    }

    // map page table into parent page table
    struct capref pt_mapping_cap;
    // allocate slot for capability
    err = st->slot_allocator->alloc(st->slot_allocator, &pt_mapping_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "slot_alloc failed");
        return err;
    }

    err = vnode_map(parent_pt->cap, pt_cap, parent_pt_index, VREGION_FLAGS_READ, 0, 1,
                    pt_mapping_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map page table");
        return err;
    }

    // reflect mapping in datastructure
    *pt = slab_alloc(&st->slab_allocator);
    if (*pt == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    (*pt)->cap = pt_cap;
    parent_pt->entries[parent_pt_index] = *pt;
    parent_pt->mappings[parent_pt_index] = &pt_mapping_cap;

    return SYS_ERR_OK;
}


/**
 * @brief mapps the provided frame at the supplied address in the paging state
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] vaddr   the virtual address to create the mapping at
 * @param[in] frame   the frame to map in
 * @param[in] bytes   the number of bytes that will be mapped.
 * @param[in] flags   The flags that are to be set for the newly mapped region,
 *                    see 'paging_flags_t' in paging_types.h .
 *
 * @return SYS_ERR_OK on success.
 */
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame_cap, size_t bytes, int flags)
{
    /*
     * TODO(M1):
     *    - Map a frame assuming all mappings will fit into one leaf page table (L3)
     * TODO(M2):
     *    - General case: you will need to handle mappings spanning multiple leaf page
     * tables.
     *    - Make sure to update your paging state to reflect the newly mapped region
     *
     * Hint:
     *  - think about what mapping configurations are actually possible
     *
     * use the current variable
     */

    // ASK: different of 'current' and 'st'?

    // based on assumptions:
    // * the frame you are trying to map always fits inside a single L3 page-table
    // * the virtual address is chosen such that it does not overlap
    assert(bytes % 4096 == 0);

    errval_t err;

    size_t page_offset = 12;
    uint16_t page_index_size = 9;
    uint16_t last_bits = (1 << page_index_size) - 1;
    size_t l0_index = (vaddr >> (3 * page_index_size + page_offset)) & last_bits;
    size_t l1_index = (vaddr >> (2 * page_index_size + page_offset)) & last_bits;
    size_t l2_index = (vaddr >> (1 * page_index_size + page_offset)) & last_bits;
    size_t l3_index = (vaddr >> (0 * page_index_size + page_offset)) & last_bits;


    struct page_table *l0_pt = &st->root_page_table;
    struct page_table *l1_pt = NULL;
    err = paging_get_or_create_pt(st, l0_pt, l0_index, ObjType_VNode_AARCH64_l1, &l1_pt);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get/create l1 page table");
        return err_push(err, LIB_ERR_PMAP_MAP);
    }

    struct page_table *l2_pt = NULL;
    err = paging_get_or_create_pt(st, l1_pt, l1_index, ObjType_VNode_AARCH64_l2, &l2_pt);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get/create l2 page table");
        return err_push(err, LIB_ERR_PMAP_MAP);
    }

    struct page_table *l3_pt = NULL;
    err = paging_get_or_create_pt(st, l2_pt, l2_index, ObjType_VNode_AARCH64_l3, &l3_pt);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get/create l3 page table");
        return err_push(err, LIB_ERR_PMAP_MAP);
    }
    
    for (int i = 0; i < bytes / BASE_PAGE_SIZE; i++) {
        assert(l3_index + i < PTABLE_ENTRIES);

        if (l3_pt->mappings[l3_index + i] != NULL) {
            return LIB_ERR_PMAP_EXISTING_MAPPING;
        }

        struct capref frame_mapping_cap;
        err = st->slot_allocator->alloc(st->slot_allocator, &frame_mapping_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "slot_alloc failed");
            return err;
        }

        err = vnode_map(l3_pt->cap, frame_cap, l3_index + i, VREGION_FLAGS_READ_WRITE,
                        i * BASE_PAGE_SIZE, 1, frame_mapping_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to map page table");
            return err;
        }

        l3_pt->mappings[l3_index + i] = &frame_mapping_cap;
    }

    return SYS_ERR_OK;
}


/**
 * @brief Unmaps the region starting at the supplied pointer.
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] region  starting address of the region to unmap
 *
 * @return SYS_ERR_OK on success, or error code indicating the kind of failure
 *
 * The supplied `region` must be the start of a previously mapped frame.
 *
 * @NOTE: Implementing this function is optional.
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    // TODO -> optional
    return LIB_ERR_NOT_IMPLEMENTED;
}
