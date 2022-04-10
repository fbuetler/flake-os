/**
 * \file
 * \brief PMAP Implementaiton for AOS
 */

/*
 * Copyright (c) 2019 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef PAGING_TYPES_H_
#define PAGING_TYPES_H_ 1

#include <aos/solution.h>
#include <mm/mm_tracker.h>
#include "collections/list.h"
#include <collections/hash_table.h>

#define VADDR_OFFSET ((lvaddr_t)512UL * 1024 * 1024 * 1024)  // 1GB
#define VADDR_MIN (0x0000000000000000UL)
#define VADDR_MAX (0xffffffffffffffffUL)

#define VADDR_MIN_USERSPACE (0x0000000000000000UL)
#define VADDR_MAX_USERSPACE (0x0000ffffffffffffUL)

#define VREGION_FLAGS_READ 0x01     // Reading allowed
#define VREGION_FLAGS_WRITE 0x02    // Writing allowed
#define VREGION_FLAGS_EXECUTE 0x04  // Execute allowed
#define VREGION_FLAGS_NOCACHE 0x08  // Caching disabled
#define VREGION_FLAGS_MPB 0x10      // Message passing buffer
#define VREGION_FLAGS_GUARD 0x20    // Guard page
#define VREGION_FLAGS_MASK 0x2f     // Mask of all individual VREGION_FLAGS

#define VREGION_FLAGS_READ_WRITE (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE)
#define VREGION_FLAGS_READ_EXECUTE (VREGION_FLAGS_READ | VREGION_FLAGS_EXECUTE)
#define VREGION_FLAGS_READ_WRITE_NOCACHE                                                 \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_NOCACHE)
#define VREGION_FLAGS_READ_WRITE_MPB                                                     \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_MPB)

#define L0_IDX_OFFSET 39
#define L1_IDX_OFFSET 30
#define L2_IDX_OFFSET 21
#define L3_IDX_OFFSET 12

#define L0_IDX_MASK (MASK(9) << L0_IDX_OFFSET)
#define L1_IDX_MASK (MASK(9) << L1_IDX_OFFSET)
#define L2_IDX_MASK (MASK(9) << L2_IDX_OFFSET)
#define L3_IDX_MASK (MASK(9) << L3_IDX_OFFSET)

#define L0_IDX(addr) ((uint16_t)((addr & L0_IDX_MASK) >> L0_IDX_OFFSET))
#define L1_IDX(addr) ((uint16_t)((addr & L1_IDX_MASK) >> L1_IDX_OFFSET))
#define L2_IDX(addr) ((uint16_t)((addr & L2_IDX_MASK) >> L2_IDX_OFFSET))
#define L3_IDX(addr) ((uint16_t)((addr & L3_IDX_MASK) >> L3_IDX_OFFSET))

#define EXCEPTION_STACK_SIZE (16UL * 1024)     // 16 Kb
#define EXCEPTION_STACK_MIN_SIZE (4UL * 1024)  // 4Kb

typedef int paging_flags_t;

// struct to store a page table
struct page_table {
    struct capref cap;  ///< cap that represent the memory where this page table is stored
    struct page_table *entries[PTABLE_ENTRIES];  ///< the entries of the page table
    struct capref mappings[PTABLE_ENTRIES];      ///< the mapping of the page table
    genpaddr_t paddrs[PTABLE_ENTRIES];
    uint16_t filled_slots;  ///< nr of filled slots in this table
};

// struct to be used as the value of vspace_lookup
struct vaddr_region {
    genvaddr_t vaddr;
    gensize_t bytes;
};

/*
paddr -> (vaddr, page size): hashmaps

lookup(paddr):
    vaddr, size = lookup(ROUND_DOWN(paddr, BASE_PAGESIZE))
    vaddr, size = lookup(ROUND_DOWN(paddr, Super_PAGESIZE))
    vaddr, size = lookup(ROUND_DOWN(paddr, Super_duper_PAGESIZE))

put(paddr, vaddr, size):
    store

<XXXXX><----><----->
                x
*/

// struct to store the paging status of a process
struct paging_state {
    struct slot_allocator *slot_allocator;  ///< Slab allocator used for allocating
                                            ///< page tables
    struct slab_allocator slab_allocator;   ///< Slot allocator for allocating cspac
    struct page_table root_page_table;      ///< L0 page table
    collections_hash_table *vspace_lookup;  ///< Hashmap to lookup the virtual
                                            ///< address given a physical address

    mm_tracker_t vspace_tracker;                  ///< mm tracker for vspace
    struct slab_allocator vspace_slab_allocator;  ///< Slab allocator for allocating vspace
};

#endif  /// PAGING_TYPES_H_