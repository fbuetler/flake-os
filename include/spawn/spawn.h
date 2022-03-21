/**
 * \file
 * \brief create child process library
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_SPAWN_H_
#define _INIT_SPAWN_H_

#include "aos/slot_alloc.h"
#include "aos/paging.h"


struct spawninfo {
    // the next in the list of spawned domains
    struct spawninfo *next;

    // Information about the binary
    char *binary_name;  // Name of the binary

    struct mem_region *module;  // same name as in the book

    // TODO(M2): Add fields you need to store state
    //           when spawning a new dispatcher,
    //           e.g. references to the child's
    //           capabilities or paging state
    struct cnoderef rootcn;
    struct capref rootcn_cap;

    struct cnoderef taskcn;
    struct cnoderef basepagecn;
    struct cnoderef pagecn;
};

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid);
errval_t allocator_fn(void *state, genvaddr_t base, size_t size, uint32_t flags,
                      void **ret);


#endif /* _INIT_SPAWN_H_ */
