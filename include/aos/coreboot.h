/**
 * \file coreboot.h
 * \brief boot new core
 */

/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef LIBBARRELFISH_COREBOOT_H
#define LIBBARRELFISH_COREBOOT_H

#include <sys/cdefs.h>
#include "types.h"

__BEGIN_DECLS

/**
 * \brief Boot a core
 *
 * \param mpid          The ARM MPID of the core to be booted    
 * \param boot_driver   Name of the boot driver binary
 * \param cpu_driver    Name of the CPU driver
 * \param init          The name of the init binary
 * \param urpc_frame_id Description of what will be passed as URPC frame
 *
 */
errval_t coreboot(coreid_t mpid,
        const char *boot_driver,
        const char *cpu_driver,
        const char *init,
        struct frame_identity urpc_frame_id);

struct mem_info {
    size_t                size;      // Size in bytes of the memory region
    void                  *buf;      // Address where the region is currently mapped
    lpaddr_t              phys_base; // Physical base address
};


errval_t allocate_page_core_data(void);
errval_t allocate_stack_memory(void);
errval_t get_cpu_entrypoint(void);
errval_t get_boot_entrypoint(void);
errval_t flush_cache(void);
errval_t spawn_core(hwid_t core_id, enum cpu_type cpu_type, genpaddr_t entry, genpaddr_t context, uint64_t psci_use_hvc);
errval_t relocate_drivers(genvaddr_t binary, struct mem_info *mem_info);
errval_t load_binaries(genvaddr_t binary, struct mem_info *mem, genvaddr_t entry_point, genvaddr_t *reloc_entry_point);
errval_t get_kcb(struct capref *kcb_cap);

__END_DECLS

#endif
