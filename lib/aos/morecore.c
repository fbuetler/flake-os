/**
 * \file
 * \brief Morecore implementation for malloc
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011, 2019 ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/morecore.h>
#include <stdio.h>

typedef void *(*morecore_alloc_func_t)(size_t bytes, size_t *retbytes);
extern morecore_alloc_func_t sys_morecore_alloc;

typedef void (*morecore_free_func_t)(void *base, size_t bytes);
extern morecore_free_func_t sys_morecore_free;

// this define makes morecore use an implementation that just has a static
// 16MB heap.
// TODO (M4): use a dynamic heap instead,
//#define USE_STATIC_HEAP

#ifdef USE_STATIC_HEAP

// dummy mini heap (16M)

#    define HEAP_SIZE (1 << 24)

static char mymem[HEAP_SIZE] = { 0 };
static char *endp = mymem + HEAP_SIZE;

/**
 * \brief Allocate some memory for malloc to use
 *
 * This function will keep trying with smaller and smaller frames till
 * it finds a set of frames that satisfy the requirement. retbytes can
 * be smaller than bytes if we were able to allocate a smaller memory
 * region than requested for.
 */
static void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    DEBUG_PRINTF("morecore alloc called \n");
    struct morecore_state *state = get_morecore_state();

    size_t aligned_bytes = ROUND_UP(bytes, sizeof(Header));
    void *ret = NULL;
    if (state->freep + aligned_bytes < endp) {
        ret = state->freep;
        state->freep += aligned_bytes;
    } else {
        aligned_bytes = 0;
    }
    *retbytes = aligned_bytes;
    return ret;
}

static void morecore_free(void *base, size_t bytes)
{
    return;
}

errval_t morecore_init(size_t alignment)
{
    struct morecore_state *state = get_morecore_state();

    debug_printf("initializing static heap\n");

    thread_mutex_init(&state->mutex);

    state->freep = mymem;

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;
    return SYS_ERR_OK;
}

errval_t morecore_reinit(void)
{
    return SYS_ERR_OK;
}

#else
// dynamic heap using lib/aos/paging features

/**
 * \brief Allocate some memory for malloc to use
 *
 * This function will keep trying with smaller and smaller frames till
 * it finds a set of frames that satisfy the requirement. retbytes can
 * be smaller than bytes if we were able to allocate a smaller memory
 * region than requested for.
 */
static void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    errval_t err;
    DEBUG_PRINTF("morecore dynamic called \n");

    struct morecore_state *st = get_morecore_state();

    // reserve a region of virtual memory for the heap
    size_t aligned_bytes = ROUND_UP(bytes, sizeof(Header));
    void *buf;
    err = paging_alloc_region(st->paging_state, VREGION_TYPE_HEAP, &buf, aligned_bytes, 1);
    DEBUG_PRINTF("after paging_alloc in morecore\n");
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate a virtual memory for heap");
        return NULL;
    }
    DEBUG_PRINTF("before retbytes morecore\n");
    debug_printf("aligned bytes from morecore alloc: 0x%lx\n", aligned_bytes);
    *retbytes = aligned_bytes;

    DEBUG_PRINTF("after retbytes morecore\n");
    // debug_printf("reserved (0x%lx, 0x%lx)\n", buf, *retbytes);
    // mm_tracker_debug_print(&get_current_paging_state()->vheap_tracker);

    DEBUG_PRINTF("returning addr from morecore_alloc: 0x%zx , &buf: 0x%zx\n", buf, &buf);
    return buf;
}

static void morecore_free(void *base, size_t bytes)
{
    errval_t err;

    struct morecore_state *st = get_morecore_state();

    err = paging_unmap(st->paging_state, base);
    if (err_is_fail(err)) {
        if (err == MM_ERR_MMT_FIND_ALLOCATED_NODE) {
            return;
        }
        DEBUG_ERR(err, "failed to unmap page");
        return;
    }
}

errval_t morecore_init(size_t alignment)
{
    debug_printf("initializing dynamic heap\n");

    struct morecore_state *st = get_morecore_state();

    thread_mutex_init(&st->mutex);

    // mm_tracker_debug_print(&get_current_paging_state()->vheap_tracker);
    st->paging_state = get_current_paging_state();


    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;


    return SYS_ERR_OK;
}

errval_t morecore_reinit(void)
{
    // TODO do we have to do something here?
    return SYS_ERR_OK;
}

#endif

Header *get_malloc_freep(void);
Header *get_malloc_freep(void)
{
    return get_morecore_state()->header_freep;
}
