/**
 * \file
 * \brief Memory manager header
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

#ifndef AOS_MM_H
#define AOS_MM_H

#include <sys/cdefs.h>
#include <errors/errno.h>
#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include "slot_alloc.h"
#include "list.h"
#include "map.h"

__BEGIN_DECLS

/*
 * The minimum allocation size is 1 page i.e. 4KB
 */
#define MIN_ALLOC_LOG2 12  // TODO
#define MIN_ALLOC ((size_t)1 << MIN_ALLOC_LOG2)

/*
 * The maxmimum allocation size is 2GB
 */
#define MAX_ALLOC_LOG2 31  // TODO
#define MAX_ALLOC ((size_t)1 << MAX_ALLOC_LOG2)

/*
 * For every region size of a power of two has bucket.
 * Every bucket stores the free list of its region size.
 */
#define BUCKET_COUNT (MAX_ALLOC_LOG2 - MIN_ALLOC_LOG2 + 1)


/**
 * \brief Memory manager instance data
 *
 * This should be opaque from the perspective of the client, but to allow
 * them to allocate its memory, we declare it in the public header.
 */
struct mm {
    struct slab_allocator slabs;  ///< Slab allocator used for allocating nodes
    slot_alloc_t slot_alloc;      ///< Slot allocator for allocating cspace
    slot_refill_t slot_refill;    ///< Slot allocator refill function
    void *slot_alloc_inst;        ///< Opaque instance pointer for slot allocator
    enum objtype objtype;         ///< Type of capabilities stored

    list_t *buckets[BUCKET_COUNT];  // array of douply linked list of free memory
    map_t *allocations;             // map of allocated memory with (address, size)
    size_t base_addr;               // base address of memory TODO FIXME multiple regions
    bool added;                     // TODO FIXME: handle multiple regions
};

errval_t mm_init(struct mm *mm, enum objtype objtype, slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func, slot_refill_t slot_refill_func,
                 void *slot_alloc_inst);
errval_t mm_add(struct mm *mm, struct capref cap);
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                          struct capref *retcap);
errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap);
errval_t mm_free(struct mm *mm, struct capref cap);
void mm_destroy(struct mm *mm);

__END_DECLS

#endif /* AOS_MM_H */
