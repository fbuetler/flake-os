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

// uncomment for demo
#define PRINT_PT_CREATION

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

static void page_fault_exception_handler(enum exception_type type, int subtype,
                                         void *addr, arch_registers_state_t *regs)
{
    debug_printf("page fault exception handler entered\n");
    debug_printf("type: %d\n", type);        // exception_type
    debug_printf("subtype: %d\n", subtype);  // pagefault_exception_type
    debug_printf("addr: 0x%lx\n", addr);

    // TODO recommended
    // * detect NULL pointer dereferences
    // * disallowing any mapping outside the ranges that you defined as valid for heap, stack
    // * add a guard page to the process’ stack

    // TODO servicing the page fault: install a newly acquired page of RAM at the faulting
    // address with paging_map_fixed_attr()

    // TODO resuming the thread.
}

#define INTERNAL_STACK_SIZE (1 << 14)
static char internal_ex_stack[INTERNAL_STACK_SIZE];

static errval_t paging_set_exception_handler(char *stack_base, size_t stack_size)
{
    errval_t err;

    char *stack_top = NULL;
    if (stack_base && stack_size >= 4096u) {
        stack_top = stack_base + stack_size;
    } else {  // use our exception stack region
        stack_base = internal_ex_stack;
        stack_top = stack_base + INTERNAL_STACK_SIZE;
    }

    exception_handler_fn old_handler;
    void *old_stack_base, *old_stack_top;
    err = thread_set_exception_handler(page_fault_exception_handler, &old_handler,
                                       stack_base, stack_top, &old_stack_base,
                                       &old_stack_top);
    return SYS_ERR_OK;
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

    errval_t err;

    // store root page table L0
    st->root_page_table.cap = pdir;
    // store slot allocator
    st->slot_allocator = ca;

    // add one node to mmt for whole vspace
    mmnode_t *node;
    err = mm_tracker_alloc(&st->vspace_tracker, &node);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to allocate the ROOT node in the VSpace");
        return err_push(err, MM_ERR_ALLOC_NODE);
    }

    size_t initial_size = BIT(50);
    node->type = NodeType_Free;
    node->capinfo
        = (struct capinfo) { .cap = NULL_CAP, .base = start_vaddr, .size = initial_size };
    node->base = start_vaddr;
    node->size = initial_size;
    node->next = NULL;
    node->prev = NULL;
    mm_tracker_node_insert(&st->vspace_tracker, node);

    // set page fault exception handler
    err = paging_set_exception_handler(NULL, 0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }

    return SYS_ERR_OK;
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
    assert(st != NULL);

    errval_t err;

    // allocate frame for paging slab allocator
    struct capref paging_slab_frame;
    size_t paging_slab_frame_allocated_size;
    err = frame_alloc(&paging_slab_frame, SLAB_STATIC_SIZE(64, sizeof(struct page_table)),
                      &paging_slab_frame_allocated_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated frame");
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    // map frame for paging slab allocator
    void *paging_slab_frame_addr;
    err = paging_map_frame_attr(get_current_paging_state(), &paging_slab_frame_addr,
                                paging_slab_frame_allocated_size, paging_slab_frame,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map frame");
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    // give frame to paging slab allocator
    slab_init(&st->slab_allocator, sizeof(struct page_table), pt_slab_default_refill);
    slab_grow(&st->slab_allocator, paging_slab_frame_addr,
              paging_slab_frame_allocated_size);

    // allocate frame for virtual memory allocator
    struct capref vmm_slab_frame;
    size_t vmm_slab_frame_allocated_size;
    err = frame_alloc(&vmm_slab_frame, SLAB_STATIC_SIZE(64, sizeof(mmnode_t)),
                      &vmm_slab_frame_allocated_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated frame");
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    // map frame for virtual memory slab allocator
    void *vmm_slab_frame_addr;
    err = paging_map_frame_attr(get_current_paging_state(), &vmm_slab_frame_addr,
                                vmm_slab_frame_allocated_size, vmm_slab_frame,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map frame");
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    // give virtual memory slab allocator some memory
    mm_tracker_init(&st->vspace_tracker, &st->vspace_slab_allocator);
    slab_grow(&st->vspace_slab_allocator, vmm_slab_frame_addr,
              vmm_slab_frame_allocated_size);

    err = paging_init_state(st, start_vaddr, pdir, ca);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }

    return SYS_ERR_OK;
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
    errval_t err;

    set_current_paging_state(&current);
    struct paging_state *st = &current;

    // give paging slab allocator some memory
    slab_init(&st->slab_allocator, sizeof(struct page_table), pt_slab_default_refill);
    static uint8_t pt_buf[SLAB_STATIC_SIZE(16, sizeof(struct page_table))];
    slab_grow(&st->slab_allocator, pt_buf, sizeof(pt_buf));

    // give virtual memory slab allocator some memory
    mm_tracker_init(&st->vspace_tracker, &st->vspace_slab_allocator);
    static uint8_t vspace_buf[SLAB_STATIC_SIZE(16, sizeof(mmnode_t))];
    slab_grow(&st->vspace_slab_allocator, vspace_buf, sizeof(vspace_buf));

    // init paging state
    err = paging_init_state(st, VADDR_OFFSET, cap_vroot, get_default_slot_allocator());
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }

    return SYS_ERR_OK;
}

int paging_lock = 0;
static void paging_refill(struct paging_state *st)
{
    if (!paging_lock) {
        paging_lock = 1;
        if (slab_freecount(&st->slab_allocator) < 10) {
            assert(err_is_ok(st->slab_allocator.refill_func(&st->slab_allocator)));
        }
        paging_lock = 0;
    }
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

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);
    errval_t err;

    // DEBUG_TRACEF("Map frame to free addr: get next fit\n");
    mmnode_t *frame_region;
    err = mm_tracker_get_next_fit(&st->vspace_tracker, &frame_region, bytes,
                                  BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to get next fit in paging_map_frame_attr");
        return err_push(err, MM_ERR_FIND_NODE);
    }

    // DEBUG_TRACEF("Map frame to free addr: frame address 0x%lx\n", frame_region->base);
    if (buf != NULL) {
        *buf = (void *)frame_region->base;
    }

    return SYS_ERR_OK;
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
 *
 * @note If buf==NULL, the base address will not be passed back.
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
    errval_t err;

    assert(st != NULL);

    DEBUG_TRACEF("Map frame to free addr: Refill slabs\n");
    mm_tracker_refill(&st->vspace_tracker);
    paging_refill(st);

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    DEBUG_TRACEF("Map frame to free addr: allocate virtual memory\n");
    err = paging_alloc(st, buf, bytes, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate a virtual memory");
        return err_push(err, LIB_ERR_PAGING_MAP_FIXED);
    }

    // DEBUG_PRINTF("Map frame to free addr: map frame at %lx\n", *buf);

    err = paging_map_fixed_attr(st, (lvaddr_t)*buf, frame, bytes, flags);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map frame");
        return err_push(err, LIB_ERR_PAGING_MAP_FIXED);
    }

    return SYS_ERR_OK;
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

    assert(parent_pt_index < 512);

    err = vnode_map(parent_pt->cap, pt_cap, parent_pt_index, VREGION_FLAGS_READ, 0, 1,
                    pt_mapping_cap);
    if (err_is_fail(err)) {
        if (parent_pt->entries[parent_pt_index]) {
            // TODO make this cleaner!
            *pt = parent_pt->entries[parent_pt_index];
            err = cap_destroy(pt_cap);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "couldn't destroy cap");
                return err;
            }
            return SYS_ERR_OK;
        }

        DEBUG_ERR(err, "failed to map page table");
        return err;
    }

#ifdef DEMO_M2
    int lvl;
    if (pt_type == ObjType_VNode_AARCH64_l0) {
        lvl = 0;
    } else if (pt_type == ObjType_VNode_AARCH64_l1) {
        lvl = 1;
    } else if (pt_type == ObjType_VNode_AARCH64_l2) {
        lvl = 2;
    } else {
        lvl = 3;
    }

    printf("created L%d page table in %p slot %d\n", lvl, parent_pt, parent_pt_index);
#endif

    // reflect mapping in datastructure
    *pt = slab_alloc(&st->slab_allocator);
    if (*pt == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    (*pt)->cap = pt_cap;
    (*pt)->filled_slots = 0;
    for (int i = 0; i < 512; i++) {
        (*pt)->mappings[i] = NULL_CAP;
        (*pt)->entries[i] = NULL;
    }

    parent_pt->entries[parent_pt_index] = *pt;
    parent_pt->mappings[parent_pt_index] = pt_mapping_cap;
    parent_pt->filled_slots++;

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

    // based on assumptions:
    // * the frame you are trying to map always fits inside a single L3 page-table
    // * the virtual address is chosen such that it does not overlap
    assert(bytes % BASE_PAGE_SIZE == 0);
    assert(vaddr % BASE_PAGE_SIZE == 0);


    errval_t err;

    // DEBUG_TRACEF("Map frame to fixed addr: Allocating range\n");
    mmnode_t *allocated_node;
    err = mm_tracker_alloc_range(&st->vspace_tracker, vaddr, bytes, &allocated_node);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "mm_tracker_alloc_range failed");
        err = err_push(err, MM_ERR_MMT_ALLOC_RANGE);
        return err;
    }
    // DEBUG_TRACEF("Map frame to fixed addr: Allocated range\n");

    size_t allocated_bytes = 0;

    struct page_table *l0_pt = &st->root_page_table;
    struct page_table *l1_pt;
    struct page_table *l2_pt;
    struct page_table *l3_pt;
    bool do_recompute = true;

    // DEBUG_TRACEF("Map frame to fixed addr: Update page tables\n");
    while (allocated_bytes < bytes) {
        // DEBUG_TRACEF("Map frame to fixed addr: Virtual address 0x%lx\n", vaddr);
        size_t l0_index = L0_IDX(vaddr);
        size_t l1_index = L1_IDX(vaddr);
        size_t l2_index = L2_IDX(vaddr);
        size_t l3_index = L3_IDX(vaddr);

        assert(l0_index < 512);
        assert(l1_index < 512);
        assert(l2_index < 512);
        assert(l3_index < 512);


        if (do_recompute) {
            // TODO: make efficient
            // DEBUG_TRACEF("Map frame to fixed addr: Get/create L1 page table\n");
            l1_pt = NULL;
            err = paging_get_or_create_pt(st, l0_pt, l0_index, ObjType_VNode_AARCH64_l1,
                                          &l1_pt);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get/create l1 page table");
                err = err_push(err, LIB_ERR_PMAP_MAP);
                goto unwind_allocated_vnode;
            }

            // DEBUG_TRACEF("Map frame to fixed addr: Get/create L2 page table\n");
            l2_pt = NULL;
            err = paging_get_or_create_pt(st, l1_pt, l1_index, ObjType_VNode_AARCH64_l2,
                                          &l2_pt);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get/create l2 page table");
                err = err_push(err, LIB_ERR_PMAP_MAP);
                goto unwind_allocated_vnode;
            }

            // DEBUG_TRACEF("Map frame to fixed addr: Get/create L3 page table\n");
            l3_pt = NULL;
            err = paging_get_or_create_pt(st, l2_pt, l2_index, ObjType_VNode_AARCH64_l3,
                                          &l3_pt);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get/create l3 page table");
                err = err_push(err, LIB_ERR_PMAP_MAP);
                goto unwind_allocated_vnode;
            }
        }

        // DEBUG_TRACEF("Map frame to fixed addr: Map frame in L3 page table at %d\n",
        //             l3_index);

        if (capcmp(l3_pt->mappings[l3_index], NULL_CAP) == 0) {
            err = LIB_ERR_PMAP_EXISTING_MAPPING;
            goto unwind_allocated_vnode;
        }

        struct capref frame_mapping_cap;
        err = st->slot_allocator->alloc(st->slot_allocator, &frame_mapping_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "slot_alloc failed");
            err = err_push(err, LIB_ERR_SLOT_ALLOC);
            goto unwind_allocated_vnode;
        }

        err = vnode_map(l3_pt->cap, frame_cap, l3_index, flags, allocated_bytes, 1,
                        frame_mapping_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to map page table");
            err = err_push(err, LIB_ERR_VNODE_MAP);
            goto unwind_allocated_vnode;
        }

        l3_pt->mappings[l3_index] = frame_mapping_cap;
        l3_pt->filled_slots++;

        vaddr += BASE_PAGE_SIZE;
        allocated_bytes += BASE_PAGE_SIZE;

        if (l1_index == 511 || l2_index == 511 || l3_index == 511) {
            do_recompute = true;
        } else {
            do_recompute = false;
        }
    }

    // DEBUG_TRACEF("Map frame to fixed addr: Refill slabs\n");
    mm_tracker_refill(&st->vspace_tracker);


    // mm_tracker_debug_print(&st->vspace_tracker);
    // DEBUG_TRACEF("Map frame to fixed addr: Mapped frame\n");

    return SYS_ERR_OK;

unwind_allocated_vnode:;

    errval_t free_err = mm_tracker_free(&st->vspace_tracker, allocated_node->base,
                                        allocated_node->size);
    if (err_is_fail(free_err)) {
        DEBUG_ERR(free_err, "failed to free allocated node");
        err = err_push(err, free_err);
    }

    return err;
}


static errval_t paging_pt_unmap_slot(struct paging_state *st, struct page_table *pt,
                                     uint16_t slot_index)
{
    errval_t err;
    err = cap_destroy(pt->mappings[slot_index]);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_DELETE);
    }

    struct page_table *child_pt = pt->entries[slot_index];

    pt->mappings[slot_index] = NULL_CAP;
    pt->entries[slot_index] = NULL;
    pt->filled_slots--;

    err = cap_destroy(child_pt->cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_DELETE);
    }

    slab_free(&st->slab_allocator, child_pt);

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

    /*
        1. find node belonging to region
        2. iterate by BASE_PAGE_SIZE steps
            2.1. free l3 slot
                => if l3 empty: delete l3
                    => if l2 empty: delete l2
                        => if l1 empty: delete l1
    */
    errval_t err;

    // 1. find node belonging to region
    mmnode_t *allocated_node;
    err = mm_tracker_find_allocated_node(&st->vspace_tracker, (genpaddr_t)region,
                                         &allocated_node);

    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_MMT_FIND_ALLOCATED_NODE);
    }

    genpaddr_t current_vaddr = (genpaddr_t)region;
    genpaddr_t end_vaddr = current_vaddr + allocated_node->size;


    struct page_table *l0_pt = &st->root_page_table;
    struct page_table *l1_pt;
    struct page_table *l2_pt;
    struct page_table *l3_pt;

    bool do_recompute = true;

    while (current_vaddr != end_vaddr) {
        size_t l0_index = L0_IDX(current_vaddr);
        size_t l1_index = L1_IDX(current_vaddr);
        size_t l2_index = L2_IDX(current_vaddr);
        size_t l3_index = L3_IDX(current_vaddr);

        assert(l0_index < 512);
        assert(l1_index < 512);
        assert(l2_index < 512);
        assert(l3_index < 512);

        // get l1, l2, l3 levels

        if (do_recompute) {
            l1_pt = NULL;
            err = paging_get_or_create_pt(st, l0_pt, l0_index, ObjType_VNode_AARCH64_l1,
                                          &l1_pt);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get l1 page table");
                err = err_push(err, LIB_ERR_PMAP_MAP);
                return err;
            }

            // DEBUG_TRACEF("Map frame to fixed addr: Get/create L2 page table\n");
            l2_pt = NULL;
            err = paging_get_or_create_pt(st, l1_pt, l1_index, ObjType_VNode_AARCH64_l2,
                                          &l2_pt);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get l2 page table");
                err = err_push(err, LIB_ERR_PMAP_MAP);
                return err;
            }

            // DEBUG_TRACEF("Map frame to fixed addr: Get/create L3 page table\n");
            l3_pt = NULL;
            err = paging_get_or_create_pt(st, l2_pt, l2_index, ObjType_VNode_AARCH64_l3,
                                          &l3_pt);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get l3 page table");
                err = err_push(err, LIB_ERR_PMAP_MAP);
                return err;
            }
        }

        if (l3_index == 511 || l2_index == 511 || l1_index == 511) {
            do_recompute = true;
        } else {
            do_recompute = false;
        }

        // free the frame slot manually
        err = cap_destroy(l3_pt->mappings[l3_index]);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }

        l3_pt->mappings[l3_index] = NULL_CAP;
        l3_pt->filled_slots--;

        if (l3_pt->filled_slots == 0) {
            err = paging_pt_unmap_slot(st, l2_pt, l2_index);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("Failed to unmap l3 page table at l2 index %x\n", l2_index);
                return err_push(err, LIB_ERR_PAGING_PT_UNMAP_SLOT);
            }
            if (l2_pt->filled_slots == 0) {
                err = paging_pt_unmap_slot(st, l1_pt, l1_index);
                if (err_is_fail(err)) {
                    DEBUG_PRINTF("Failed to unmap l2 page table at l1 index %x\n",
                                 l1_index);
                    return err_push(err, LIB_ERR_PAGING_PT_UNMAP_SLOT);
                }

                if (l1_pt->filled_slots == 0) {
                    err = paging_pt_unmap_slot(st, l0_pt, l0_index);
                    if (err_is_fail(err)) {
                        DEBUG_PRINTF("Failed to unmap l1 page table at l0 index %x\n",
                                     l0_index);
                        return err_push(err, LIB_ERR_PAGING_PT_UNMAP_SLOT);
                    }
                }
            }
        }
        current_vaddr += BASE_PAGE_SIZE;
    }

    err = mm_tracker_free(&st->vspace_tracker, (genpaddr_t)region, allocated_node->size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to free virtual memory region");
        err = err_push(err, MM_ERR_MM_FREE);
        return err;
    }

    return SYS_ERR_OK;
}
