/**
 * \file
 * \brief Barrelfish paging helpers.
 */

/*
 * Copyright (c) 2012, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */


#ifndef LIBBARRELFISH_PAGING_H
#define LIBBARRELFISH_PAGING_H

#include <errors/errno.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include <barrelfish_kpi/paging_arch.h>
#include <aos/paging_types.h>

struct paging_state;


struct thread;
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref pdir, struct slot_allocator *ca);
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref pdir, struct slot_allocator *ca);
/// initialize self-paging module
errval_t paging_init(void);

errval_t paging_init_onthread(struct thread *t);

enum vregion_type {
    VREGION_TYPE_NULL = 0,
    VREGION_TYPE_READONLY,
    VREGION_TYPE_HEAP,
    VREGION_TYPE_STACK,
};

/**
 * \brief Find a bit of free virtual address space that is large enough to
 *        accomodate a buffer of size `bytes`.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment);

errval_t paging_alloc_region(struct paging_state *st, enum vregion_type type, void **buf,
                             size_t bytes, size_t alignment);

/**
 * Functions to map a user provided frame.
 */
/// Map user provided frame with given flags while allocating VA space for it
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags);
errval_t paging_map_frame_attr_region(struct paging_state *st, enum vregion_type type,
                                      void **buf, size_t bytes, struct capref frame,
                                      int flags);
/// Map user provided frame at user provided VA with given flags.
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags);


/**
 * \brief unmap region starting at address `region`.
 * NOTE: this function is currently here to make libbarrelfish compile. As
 * noted on paging_region_unmap we ignore unmap requests right now.
 */
errval_t paging_unmap(struct paging_state *st, const void *region);


/**
 * \brief Finds a free virtual address and maps `bytes` of the supplied frame at the address
 *
 * @param[in]  st      the paging state to create the mapping in
 * @param[out] buf     returns the virtual address at which this frame has been mapped.
 * @param[in]  bytes   the number of bytes to map.
 * @param[in]  frame   the frame capability to be mapped
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
static inline errval_t paging_map_frame(struct paging_state *st, void **buf, size_t bytes,
                                        struct capref frame)
{
    return paging_map_frame_attr(st, buf, bytes, frame, VREGION_FLAGS_READ_WRITE);
}

// Forward decl
static inline errval_t frame_identify(struct capref frame, struct frame_identity *ret);


/**
 * \brief Finds a free virtual address and maps the supplied frame in full at the
 * allocated address
 *
 * @param[in]  st      the paging state to create the mapping in
 * @param[out] buf     returns the virtual address at which this frame has been mapped.
 * @param[in]  frame   the frame capability to be mapped
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
static inline errval_t paging_map_frame_complete(struct paging_state *st, void **buf,
                                                 struct capref frame)
{
    errval_t err;
    struct frame_identity id;
    err = frame_identify(frame, &id);
    if (err_is_fail(err)) {
        return err;
    }

    return paging_map_frame_attr(st, buf, id.bytes, frame, VREGION_FLAGS_READ_WRITE);
}

/**
 * @brief mapps the provided frame at the supplied address in the paging state
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] vaddr   the virtual address to create the mapping at
 * @param[in] frame   the frame to map in
 * @param[in] bytes   the number of bytes that will be mapped.
 *
 * @return SYS_ERR_OK
 */
static inline errval_t paging_map_fixed(struct paging_state *st, lvaddr_t vaddr,
                                        struct capref frame, size_t bytes)
{
    return paging_map_fixed_attr(st, vaddr, frame, bytes, VREGION_FLAGS_READ_WRITE);
}

static inline lvaddr_t paging_genvaddr_to_lvaddr(genvaddr_t genvaddr)
{
    return (lvaddr_t)genvaddr;
}

#endif  // LIBBARRELFISH_PAGING_H
