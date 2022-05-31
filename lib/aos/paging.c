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
#include <collections/hash_table.h>
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
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    errval_t err;
    err = st->slot_allocator->alloc(st->slot_allocator, ret);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "slot_alloc failed");
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "vnode_create failed");
        return err;
    }
    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
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
 * \brief handler for handling a page fault exception
 *
 * \param type of the exception (should be EXCEPT_PAGEFAULT i.e. 1)
 * \param subtype of the exception (READ (1), WRITE (2), EXECUTE (3))
 * \param addr that caused the page fault
 * \param regs current register state
 */
static void page_fault_exception_handler(enum exception_type type, int subtype,
                                         void *addr, arch_registers_state_t *regs)
{
    //DEBUG_PRINTF("=== in page fault handler for addr: 0x%lx for type: %d, subtype: %d , PC: %lx ===\n", addr, type, subtype, regs->named.pc);
    errval_t err;

    // DEBUG_PRINTF("page_fault_exception_handler stack: %p\n", regs->named.stack);

    // TODO recommended
    // * detect NULL pointer dereferences
    // * disallowing any mapping outside the ranges that you defined as valid for heap, stack
    // * add a guard page to the process’ stack
    struct paging_state *st = get_current_paging_state();
    thread_mutex_lock_nested(&st->paging_mutex);

    lvaddr_t vaddr = (lvaddr_t)addr;


    mm_tracker_t *vspace_tracker;
    if (vaddr < VREADONLY_OFFSET) {
        err = LIB_ERR_PAGING_MAP_UNUSABLE_VADDR;
        debug_printf("fault at PC: 0x%lx\n", regs->named.pc);
        USER_PANIC_ERR(err, "vadddr is in the forbidden area: %p", (void *)vaddr);
        return;
    } else if (vaddr < VHEAP_OFFSET) {
        vspace_tracker = &st->vreadonly_tracker;
    } else if (vaddr < VSTACKS_OFFSET) {
        vspace_tracker = &st->vheap_tracker;
    } else if (vaddr < VADDR_MAX_USERSPACE) {
        vspace_tracker = &st->vstack_tracker;
    } else {
        err = LIB_ERR_PAGING_MAP_INVALID_VADDR;

        DEBUG_PRINTF("fault at PC: 0x%lx\n", regs->named.pc);
        USER_PANIC_ERR(err, "vadddr is way off limits");
        goto unlock;
    }

    DEBUG_TRACEF("Map frame to free addr: Refill slabs\n");
    mm_tracker_refill(vspace_tracker);
    paging_refill(st);

    // align address to base page size
    lvaddr_t vaddr_aligned = ROUND_DOWN(vaddr, BASE_PAGE_SIZE);

    // virtual memory region has to be logically allocated before it can be mapped
    bool is_allocated = mm_tracker_is_allocated(vspace_tracker, vaddr_aligned,
                                                BASE_PAGE_SIZE);
    if (!is_allocated) {
        // TODO fault?
        DEBUG_PRINTF("unallocated region at %p\n", vaddr);
        DEBUG_PRINTF("fault at PC: 0x%lx\n", regs->named.pc);
        USER_PANIC("Unallocated region in pagefault");
    }

    // allocate a frame
    struct capref frame;
    size_t allocated_bytes;
    err = frame_alloc(&frame, BASE_PAGE_SIZE, &allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate frame");
        goto unlock;
    }
    

    if (allocated_bytes < BASE_PAGE_SIZE) {
        DEBUG_ERR(LIB_ERR_VREGION_PAGEFAULT_HANDLER, "allocated frame is not big "
                                                     "enough");
        cap_destroy(frame);
        goto unlock;
    }

    // mm_tracker_debug_print(vspace_tracker);

    // install frame at the faulting address
    err = paging_map_fixed_attr(st, vaddr_aligned, frame, allocated_bytes,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        if (err == LIB_ERR_PMAP_EXISTING_MAPPING) {
            DEBUG_PRINTF("@@@ handled page fault: was already mapped!\n");
            goto unlock;
        }
        DEBUG_ERR(err, "failed to map frame");
        goto unlock;
    }

    // TODO track that this frame is part of the heap
    // TODO track vaddr <-> paddr mapping
unlock:
    // DEBUG_PRINTF("@@@ handled page fault at %p @@@\n", addr);
    thread_mutex_unlock(&st->paging_mutex);
}

static char internal_ex_stack[EXCEPTION_STACK_SIZE];

/**
 * \brief registers a page fault exception handler.
 * If no stack_base or stack_size is provided a static piece of memory is used
 *
 * \param stack_base address to a memory region used for the exception stack
 * \param stack_size size of the exception stack
 * \return errval_t
 */
static errval_t paging_set_exception_handler(char *stack_base, size_t stack_size)
{
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    errval_t err;

    char *stack_top = NULL;
    if (stack_base && stack_size >= EXCEPTION_STACK_MIN_SIZE) {
        stack_top = stack_base + stack_size;
    } else {  // use our exception stack region
        stack_base = internal_ex_stack;
        stack_top = stack_base + EXCEPTION_STACK_SIZE;
    }

    exception_handler_fn old_handler;
    void *old_stack_base, *old_stack_top;
    err = thread_set_exception_handler(page_fault_exception_handler, &old_handler,
                                       stack_base, stack_top, &old_stack_base,
                                       &old_stack_top);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to set paging exception handler\n");
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }
    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
    return SYS_ERR_OK;
}


static errval_t setup_vspace_tracker(mm_tracker_t *vspace_tracker, lvaddr_t base,
                                     size_t size)
{
    errval_t err;

    mmnode_t *node;
    err = mm_tracker_alloc(vspace_tracker, &node);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to allocate the ROOT node in the VSpace");
        return err_push(err, MM_ERR_ALLOC_NODE);
    }

    node->type = NodeType_Free;
    node->capinfo = (struct capinfo) { .cap = NULL_CAP, .base = base, .size = size };
    node->base = base;
    node->size = size;
    node->next = NULL;
    node->prev = NULL;
    mm_tracker_node_insert(vspace_tracker, node);

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

    size_t vreadonly_size = VHEAP_OFFSET - start_vaddr;
    // add one node to mmt for whole vspace but stack and heap aka readonly
    err = setup_vspace_tracker(&st->vreadonly_tracker, start_vaddr, vreadonly_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup readonly tracker");
        return err;
    }

    // vspace tracker for heap
    err = setup_vspace_tracker(&st->vheap_tracker, VHEAP_OFFSET, VHEAP_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup heap tracker");
        return err;
    }

    // vspace tracker for stack
    err = setup_vspace_tracker(&st->vstack_tracker, VSTACKS_OFFSET, VSTACKS_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup stack tracker");
        return err;
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

    // init vspace trackers
    mm_tracker_init(&st->vreadonly_tracker, &st->vspace_slab_allocator);
    mm_tracker_init(&st->vstack_tracker, &st->vspace_slab_allocator);
    mm_tracker_init(&st->vheap_tracker, &st->vspace_slab_allocator);

    // give virtual memory slab allocator some memory
    slab_grow(&st->vspace_slab_allocator, vmm_slab_frame_addr,
              vmm_slab_frame_allocated_size);

    err = paging_init_state(st, start_vaddr, pdir, ca);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }

    thread_mutex_init(&st->paging_mutex);

    return SYS_ERR_OK;
}


/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
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
    static uint8_t pt_buf[SLAB_STATIC_SIZE(32, sizeof(struct page_table))];
    slab_grow(&st->slab_allocator, pt_buf, sizeof(pt_buf));

    // init vspace trackers
    mm_tracker_init(&st->vreadonly_tracker, &st->vspace_slab_allocator);
    mm_tracker_init(&st->vstack_tracker, &st->vspace_slab_allocator);
    mm_tracker_init(&st->vheap_tracker, &st->vspace_slab_allocator);

    // give virtual memory slab allocator some memory
    static uint8_t vspace_buf[SLAB_STATIC_SIZE(16, sizeof(mmnode_t))];
    slab_grow(&st->vspace_slab_allocator, vspace_buf, sizeof(vspace_buf));

    // init paging state
    err = paging_init_state(st, VADDR_OFFSET, cap_vroot, get_default_slot_allocator());
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }

    // set page fault exception handler
    err = paging_set_exception_handler(NULL, 0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_STATE_INIT);
    }

    thread_mutex_init(&st->paging_mutex);

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

    // DEBUG_PRINTF("paging_init_onthread: start\n");

    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    struct capref exception_frame;
    size_t exception_stack_bytes;

    errval_t err = frame_alloc(&exception_frame, EXCEPTION_STACK_SIZE,
                               &exception_stack_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate frame");
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    void *exception_stack_addr;
    err = paging_map_frame_attr(get_current_paging_state(), &exception_stack_addr,
                                exception_stack_bytes, exception_frame,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map frame");
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    t->exception_stack = exception_stack_addr;
    t->exception_stack_top = exception_stack_addr + exception_stack_bytes;
    t->exception_handler = page_fault_exception_handler;

    // DEBUG_PRINTF("paging_init_onthread: end\n");

    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
    return SYS_ERR_OK;
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
    return paging_alloc_region(st, VREGION_TYPE_HEAP, buf, bytes, alignment);
}

errval_t paging_alloc_region(struct paging_state *st, enum vregion_type type, void **buf,
                             size_t bytes, size_t alignment)
{
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    errval_t err;
    mm_tracker_t *vspace_tracker;
    switch (type) {
    case VREGION_TYPE_READONLY:
        vspace_tracker = &st->vreadonly_tracker;
        break;
    case VREGION_TYPE_HEAP:
        vspace_tracker = &st->vheap_tracker;
        break;
    case VREGION_TYPE_STACK:
        vspace_tracker = &st->vstack_tracker;
        break;
    default:
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        err = LIB_ERR_PAGING_MAP_INVALID_VADDR;
        DEBUG_ERR(err, "failed to use correct vspace");
        return err;
    }

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    // DEBUG_TRACEF("Map frame to free addr: get next fit\n");
    mmnode_t *vspace_region;
    err = mm_tracker_get_next_fit(vspace_tracker, &vspace_region, bytes, NodeType_Free,
                                  alignment);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to find free page");
        return err_push(err, MM_ERR_FIND_NODE);
    }

    mmnode_t *allocated_node;
    err = mm_tracker_alloc_range(vspace_tracker, vspace_region->base, bytes,
                                 &allocated_node);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "mm_tracker_alloc_range failed");
        err = err_push(err, MM_ERR_MMT_ALLOC_RANGE);
        return err;
    }

    // DEBUG_TRACEF("Map frame to free addr: frame address 0x%lx\n", vspace_region->base);
    if (buf != NULL) {
        *buf = (void *)vspace_region->base;
    }

    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
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

    return paging_map_frame_attr_region(st, VREGION_TYPE_HEAP, buf, bytes, frame, flags);
}

errval_t paging_map_frame_attr_region(struct paging_state *st, enum vregion_type type,
                                      void **buf, size_t bytes, struct capref frame,
                                      int flags)
{
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    errval_t err;

    mm_tracker_t *vspace_tracker;
    switch (type) {
    case VREGION_TYPE_READONLY:
        vspace_tracker = &st->vreadonly_tracker;
        break;
    case VREGION_TYPE_HEAP:
        vspace_tracker = &st->vheap_tracker;
        break;
    case VREGION_TYPE_STACK:
        vspace_tracker = &st->vstack_tracker;
        break;
    default:
        err = LIB_ERR_PAGING_MAP_INVALID_VADDR;
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to use correct vspace");
        return err;
    }

    DEBUG_TRACEF("Map frame to free addr: Refill slabs\n");
    mm_tracker_refill(vspace_tracker);
    paging_refill(st);

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    DEBUG_TRACEF("Map frame to free addr: allocate virtual memory\n");
    err = paging_alloc_region(st, type, buf, bytes, 1);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to allocate a virtual memory");
        return err_push(err, LIB_ERR_PAGING_MAP_FIXED);
    }

    err = paging_map_fixed_attr(st, (lvaddr_t)*buf, frame, bytes, flags);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to map frame");
        return err_push(err, LIB_ERR_PAGING_MAP_FIXED);
    }

    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);

    return SYS_ERR_OK;
}

static errval_t paging_get_or_create_pt(struct paging_state *st,
                                        struct page_table *parent_pt,
                                        size_t parent_pt_index, enum objtype pt_type,
                                        struct page_table **pt)
{
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);

    errval_t err;
    *pt = (parent_pt->entries)[parent_pt_index];
    if (*pt != NULL) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        return SYS_ERR_OK;
    }

    // allocate page table
    struct capref pt_cap;
    // no need to allocate a slot as this is done in pt_alloc
    err = pt_alloc(st, pt_type, &pt_cap);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to allocate page table");
        return err;
    }


    // map page table into parent page table
    struct capref pt_mapping_cap;
    // allocate slot for capability
    err = st->slot_allocator->alloc(st->slot_allocator, &pt_mapping_cap);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
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
                thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
                DEBUG_ERR(err, "couldn't destroy cap");
                return err;
            }
            thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
            return SYS_ERR_OK;
        }
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to map page table");
        DEBUG_PRINTF("pt type: %d, pt index: %d for thread: %d \n", pt_type,
                     parent_pt_index, thread_id());
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
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
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
    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
    return SYS_ERR_OK;
}

static bool paging_get(struct page_table *parent_pt, size_t parent_pt_index,
                       struct page_table **pt)
{
    *pt = (parent_pt->entries)[parent_pt_index];
    if (*pt != NULL) {
        assert(!capcmp(NULL_CAP, (*pt)->cap));
        return true;
    }
    return false;
}


static errval_t paging_walk_pt(struct paging_state *st, struct page_table **l0_pt,
                               struct page_table **l1_pt, struct page_table **l2_pt,
                               struct page_table **l3_pt, size_t l0_index,
                               size_t l1_index, size_t l2_index)
{
    thread_mutex_lock_nested(&st->paging_mutex);
    errval_t err;
    // DEBUG_TRACEF("Map frame to fixed addr: Get/create L1 page table\n");
    *l1_pt = NULL;
    err = paging_get_or_create_pt(st, *l0_pt, l0_index, ObjType_VNode_AARCH64_l1, l1_pt);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&st->paging_mutex);
        DEBUG_ERR(err, "failed to get/create l1 page table");
        err = err_push(err, LIB_ERR_PMAP_MAP);
        return err;
    }

    // DEBUG_TRACEF("Map frame to fixed addr: Get/create L2 page table\n");
    *l2_pt = NULL;
    err = paging_get_or_create_pt(st, *l1_pt, l1_index, ObjType_VNode_AARCH64_l2, l2_pt);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&st->paging_mutex);
        DEBUG_ERR(err, "failed to get/create l2 page table");
        err = err_push(err, LIB_ERR_PMAP_MAP);
        return err;
    }

    // DEBUG_TRACEF("Map frame to fixed addr: Get/create L3 page table\n");
    *l3_pt = NULL;
    err = paging_get_or_create_pt(st, *l2_pt, l2_index, ObjType_VNode_AARCH64_l3, l3_pt);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&st->paging_mutex);
        DEBUG_ERR(err, "failed to get/create l3 page table");
        err = err_push(err, LIB_ERR_PMAP_MAP);
        return err;
    }

    thread_mutex_unlock(&st->paging_mutex);
    return SYS_ERR_OK;
}

static errval_t paging_walk_pt_if_exists(struct paging_state *st,
                                         struct page_table **l0_pt,
                                         struct page_table **l1_pt,
                                         struct page_table **l2_pt,
                                         struct page_table **l3_pt, size_t l0_index,
                                         size_t l1_index, size_t l2_index)
{
    *l1_pt = NULL;
    *l2_pt = NULL;
    *l3_pt = NULL;
    thread_mutex_lock_nested(&st->paging_mutex);
    errval_t err = SYS_ERR_OK;
    // DEBUG_TRACEF("Map frame to fixed addr: Get/create L1 page table\n");
    if (!paging_get(*l0_pt, l0_index, l1_pt)) {
        // DEBUG_ERR(err, "failed to get/create l1 page table");
        err = err_push(err, LIB_ERR_PMAP_MAP);
        goto end;
    }

    // DEBUG_TRACEF("Map frame to fixed addr: Get/create L2 page table\n");
    if (!paging_get(*l1_pt, l1_index, l2_pt)) {
        // DEBUG_ERR(err, "failed to get/create l2 page table");
        err = err_push(err, LIB_ERR_PMAP_MAP);
        goto end;
    }

    // DEBUG_TRACEF("Map frame to fixed addr: Get/create L3 page table\n");
    if (!paging_get(*l2_pt, l2_index, l3_pt)) {
        // DEBUG_ERR(err, "failed to get/create l3 page table");
        err = err_push(err, LIB_ERR_PMAP_MAP);
        goto end;
    }

end:
    thread_mutex_unlock(&st->paging_mutex);
    return SYS_ERR_OK;
}


/**
 * @brief updates the map of physical addresses to virtual addresses
 *
 * @param st Paging State
 * @param paddr Physical address (Key)
 * @param vaddr Virtual address (Value 1)
 * @param bytes Bytes in region (Value 2)
 * @return errval_t
 */
__attribute__((unused)) static errval_t
paging_vspace_lookup_insert_entry(struct paging_state *st, genpaddr_t paddr,
                                  genvaddr_t vaddr, size_t bytes)
{
    return SYS_ERR_OK;
    errval_t err;

    if (!st->vspace_lookup) {
        // initialize hash map for p->v addr lookup
        // we do this lazily because the paging code initialized before
        // morecore and the hash map needs malloc..
        collections_hash_create(&st->vspace_lookup, (collections_hash_data_free)free);
    }

    struct vaddr_region *region = (struct vaddr_region *)malloc(
        sizeof(struct vaddr_region));
    if (!region) {
        err = LIB_ERR_MALLOC_FAIL;
        DEBUG_ERR(err, "failed to allocate memory for vspace_lookup "
                       "entry");
        return err;
    }
    region->vaddr = vaddr;
    region->bytes = bytes;
    // TODO currently fails when the same binary is spawned
    // as we use its static frame and therefore we have the same paddrs
    collections_hash_insert(st->vspace_lookup, paddr, region);

    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t
paging_vspace_lookup_delete_entry(struct paging_state *st, genpaddr_t paddr)
{
    return SYS_ERR_OK;

    collections_hash_delete(st->vspace_lookup, paddr);

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
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    assert(bytes % BASE_PAGE_SIZE == 0);
    assert(vaddr % BASE_PAGE_SIZE == 0);

    errval_t err;

    mm_tracker_t *vspace_tracker;
    if (vaddr < VREADONLY_OFFSET) {
        err = LIB_ERR_PAGING_MAP_UNUSABLE_VADDR;
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "vadddr is in the forbidden areas");
        return err;
    } else if (vaddr < VHEAP_OFFSET) {
        vspace_tracker = &st->vreadonly_tracker;
    } else if (vaddr < VSTACKS_OFFSET) {
        vspace_tracker = &st->vheap_tracker;
    } else if (vaddr < VADDR_MAX_USERSPACE) {
        vspace_tracker = &st->vstack_tracker;
    } else {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        err = LIB_ERR_PAGING_MAP_INVALID_VADDR;
        DEBUG_ERR(err, "vadddr is way of limits");
        return err;
    }

#define DEBUG_PAGING_MAP_FIXED_ATTR
#ifdef DEBUG_PAGING_MAP_FIXED_ATTR
    assert(mm_tracker_is_allocated(vspace_tracker, vaddr, bytes));
#endif

    struct capability c;
    err = cap_direct_identify(frame_cap, &c);
    if (err_is_fail(err)) {
        thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
        DEBUG_ERR(err, "failed to identify capability");
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }
    genpaddr_t paddr = c.u.frame.base;

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
            err = paging_walk_pt(st, &l0_pt, &l1_pt, &l2_pt, &l3_pt, l0_index, l1_index,
                                 l2_index);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to walk page table");
                return err;
            }
        }

        // DEBUG_TRACEF("Map frame to fixed addr: Map frame in L3 page table at %d\n",
        //             l3_index);
        if (capcmp(l3_pt->mappings[l3_index], NULL_CAP) == 0) {
            err = LIB_ERR_PMAP_EXISTING_MAPPING;
            return err;
        }

        struct capref frame_mapping_cap;
        err = st->slot_allocator->alloc(st->slot_allocator, &frame_mapping_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "slot_alloc failed");
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }

        err = vnode_map(l3_pt->cap, frame_cap, l3_index, flags, allocated_bytes, 1,
                        frame_mapping_cap);

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to map page table");
            return err_push(err, LIB_ERR_VNODE_MAP);
        }

        l3_pt->mappings[l3_index] = frame_mapping_cap;
        l3_pt->paddrs[l3_index] = paddr;
        l3_pt->filled_slots++;

        /*err = paging_vspace_lookup_insert_entry(st, paddr, vaddr, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to update vspace lookup");
            return err;
        }*/

        paddr += BASE_PAGE_SIZE;
        vaddr += BASE_PAGE_SIZE;
        allocated_bytes += BASE_PAGE_SIZE;

        if (l1_index == 511 || l2_index == 511 || l3_index == 511) {
            do_recompute = true;
        } else {
            do_recompute = false;
        }
    }

    // DEBUG_TRACEF("Map frame to fixed addr: Refill slabs\n");
    mm_tracker_refill(vspace_tracker);

    // mm_tracker_debug_print(&st->vspace_tracker);
    // DEBUG_TRACEF("Map frame to fixed addr: Mapped frame\n");
    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);
    return SYS_ERR_OK;
}


static errval_t paging_pt_unmap_slot(struct paging_state *st, struct page_table *pt,
                                     uint16_t slot_index)
{
    errval_t err;
    err = cap_destroy(pt->mappings[slot_index]);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not destroy cap while unmapping pt\n");
        return err_push(err, LIB_ERR_CAP_DELETE);
    }

    struct page_table *child_pt = pt->entries[slot_index];

    pt->mappings[slot_index] = NULL_CAP;
    pt->entries[slot_index] = NULL;
    pt->filled_slots--;

    err = cap_destroy(child_pt->cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not destroy cap while unmapping pt 2\n");
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
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    /*
        1. find node belonging to region
        2. iterate by BASE_PAGE_SIZE steps
            2.1. free l3 slot
                => if l3 empty: delete l3
                    => if l2 empty: delete l2
                        => if l1 empty: delete l1
    */

    // printf("looking for %p\n", region);
    // printf("!!!! PAGING UNMAP CALLED !!!! from thread: %d\n", thread_id());
    errval_t err;

    lvaddr_t vaddr = (lvaddr_t)region;

    mm_tracker_t *vspace_tracker;
    if (vaddr < VREADONLY_OFFSET) {
        err = LIB_ERR_PAGING_MAP_UNUSABLE_VADDR;
        DEBUG_ERR(err, "vadddr is in the forbidden areas");
        return err;
    } else if (vaddr < VHEAP_OFFSET) {
        vspace_tracker = &st->vreadonly_tracker;
    } else if (vaddr < VSTACKS_OFFSET) {
        vspace_tracker = &st->vheap_tracker;
    } else if (vaddr < VADDR_MAX_USERSPACE) {
        vspace_tracker = &st->vstack_tracker;
    } else {
        err = LIB_ERR_PAGING_MAP_INVALID_VADDR;
        DEBUG_ERR(err, "vadddr is way of limits");
        return err;
    }

    // 1. find node belonging to region
    mmnode_t *allocated_node;
    err = mm_tracker_find_allocated_node(vspace_tracker, vaddr, &allocated_node);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "region is not allocated\n");
        return err_push(err, MM_ERR_MMT_FIND_ALLOCATED_NODE);
    }

    genvaddr_t current_vaddr = vaddr;
    genvaddr_t end_vaddr = current_vaddr + allocated_node->size;

    struct page_table *l0_pt = &st->root_page_table;
    struct page_table *l1_pt = NULL;
    struct page_table *l2_pt = NULL;
    struct page_table *l3_pt = NULL;

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

        err = paging_walk_pt_if_exists(st, &l0_pt, &l1_pt, &l2_pt, &l3_pt, l0_index,
                                       l1_index, l2_index);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to walk page table while unmapping");
            return err;
        }

        if (l3_index == 511 || l2_index == 511 || l1_index == 511) {
            do_recompute = true;
        } else {
            do_recompute = true;
        }

        if (l3_pt) {
            // genvaddr_t paddr = l3_pt->paddrs[l3_index];
            // paging_vspace_lookup_delete_entry(st, paddr);

            if (!capcmp(l3_pt->mappings[l3_index], NULL_CAP)) {
                debug_printf("unmapping here\n");
                // free the frame slot manually
                assert(!capcmp(l3_pt->mappings[l3_index], l2_pt->mappings[l2_index]));

                err = cap_destroy(l3_pt->mappings[l3_index]);
                if (err_is_fail(err)) {
                    return err_push(err, LIB_ERR_CAP_DESTROY);
                }

                l3_pt->mappings[l3_index] = NULL_CAP;
                l3_pt->filled_slots--;
            }

            if (l3_pt->filled_slots == 0) {
                err = paging_pt_unmap_slot(st, l2_pt, l2_index);
                if (err_is_fail(err)) {
                    DEBUG_PRINTF("Failed to unmap l3 page table at l2 index %x\n",
                                 l2_index);
                    return err_push(err, LIB_ERR_PAGING_PT_UNMAP_SLOT);
                }
            }
        }


        if (l2_pt && l2_pt->filled_slots == 0) {
            err = paging_pt_unmap_slot(st, l1_pt, l1_index);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("Failed to unmap l2 page table at l1 index %x\n", l1_index);
                return err_push(err, LIB_ERR_PAGING_PT_UNMAP_SLOT);
            }
        }

        if (l1_pt && l1_pt->filled_slots == 0) {
            err = paging_pt_unmap_slot(st, l0_pt, l0_index);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("Failed to unmap l1 page table at l0 index %x\n", l0_index);
                return err_push(err, LIB_ERR_PAGING_PT_UNMAP_SLOT);
            }
        }
        current_vaddr += BASE_PAGE_SIZE;
    }

    err = mm_tracker_free(vspace_tracker, vaddr, allocated_node->size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to free virtual memory region");
        err = err_push(err, MM_ERR_MM_FREE);
        return err;
    }

    return SYS_ERR_OK;
}

errval_t paging_vaddr_to_paddr(struct paging_state *st, genvaddr_t vaddr,
                               genpaddr_t *retpaddr)
{
    errval_t err;

    struct page_table *l0_pt = &st->root_page_table;
    struct page_table *l1_pt = NULL;
    struct page_table *l2_pt = NULL;
    struct page_table *l3_pt = NULL;

    size_t l0_index = L0_IDX(vaddr);
    size_t l1_index = L1_IDX(vaddr);
    size_t l2_index = L2_IDX(vaddr);
    size_t l3_index = L3_IDX(vaddr);

    err = paging_walk_pt_if_exists(st, &l0_pt, &l1_pt, &l2_pt, &l3_pt, l0_index, l1_index,
                                   l2_index);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to walk page table");
        return err;
    }

    if (retpaddr) {
        *retpaddr = l3_pt->paddrs[l3_index];
    }

    return SYS_ERR_OK;
}


/*
6.7 - Design the Address Space Layout

0
UNUSED
TEXT/BSS
Heap

Stack
fffffff


- Heap
- Stack
- Guard Page
- Unused segment: 0 - 16KB


Operations:
    - morecore: Allocate more pages to heap
    - extra challenges: Detect stack page fault: Allocate more pages to stack

    - Efficiently:
        - Say if part of stack or heap
        - Distinguish heap from stack
        - Allocation


*/