#include <aos/aos.h>
#include <aos/coreboot.h>
#include <spawn/multiboot.h>
#include <elf/elf.h>
#include <string.h>
#include <barrelfish_kpi/arm_core_data.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/cache.h>
#include <spawn/spawn.h>

#define ARMv8_KERNEL_OFFSET 0xffff000000000000

extern struct bootinfo *bi;

struct mem_info {
    size_t size;         // Size in bytes of the memory region
    void *buf;           // Address where the region is currently mapped
    lpaddr_t phys_base;  // Physical base address
};

/**
 * Load a ELF image into memory.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF will be loaded
 * entry_point:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t load_elf_binary(genvaddr_t binary,
                                                          const struct mem_info *mem,
                                                          genvaddr_t entry_point,
                                                          genvaddr_t *reloc_entry_point)

{
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    /* Load the CPU driver from its ELF image. */
    bool found_entry_point = 0;
    bool loaded = 0;

    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                         ", memory size 0x%" PRIx64 " SKIP\n",
                         i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);
            continue;
        }

        DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                     ", memory size 0x%" PRIx64 " LOAD\n",
                     i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);


        if (loaded) {
            USER_PANIC("Expected one load able segment!\n");
        }
        loaded = 1;

        void *dest = mem->buf;
        lpaddr_t dest_phys = mem->phys_base;

        assert(phdr[i].p_offset + phdr[i].p_memsz <= mem->size);

        /* copy loadable part */
        memcpy(dest, (void *)(binary + phdr[i].p_offset), phdr[i].p_filesz);

        /* zero out BSS section */
        memset(dest + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

        if (!found_entry_point) {
            if (entry_point >= phdr[i].p_vaddr
                && entry_point - phdr[i].p_vaddr < phdr[i].p_memsz) {
                *reloc_entry_point = (dest_phys + (entry_point - phdr[i].p_vaddr));
                found_entry_point = 1;
            }
        }
    }

    if (!found_entry_point) {
        USER_PANIC("No entry point loaded\n");
    }

    return SYS_ERR_OK;
}

/**
 * Relocate an already loaded ELF image.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF is loaded
 * kernel_:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t
relocate_elf(genvaddr_t binary, struct mem_info *mem, lvaddr_t load_offset)
{
    DEBUG_PRINTF("Relocating image.\n");

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    size_t shnum = ehdr->e_shnum;
    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    struct Elf64_Shdr *shead = (struct Elf64_Shdr *)(binary + (uintptr_t)ehdr->e_shoff);

    /* Search for relocaton sections. */
    for (size_t i = 0; i < shnum; i++) {
        struct Elf64_Shdr *shdr = &shead[i];
        if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if (shdr->sh_info != 0) {
                DEBUG_PRINTF("I expected global relocations, but got"
                             " section-specific ones.\n");
                return ELF_ERR_HEADER;
            }


            uint64_t segment_elf_base = phdr[0].p_vaddr;
            uint64_t segment_load_base = mem->phys_base;
            uint64_t segment_delta = segment_load_base - segment_elf_base;
            uint64_t segment_vdelta = (uintptr_t)mem->buf - segment_elf_base;

            size_t rsize;
            if (shdr->sh_type == SHT_REL) {
                rsize = sizeof(struct Elf64_Rel);
            } else {
                rsize = sizeof(struct Elf64_Rela);
            }

            assert(rsize == shdr->sh_entsize);
            size_t nrel = shdr->sh_size / rsize;

            void *reldata = (void *)(binary + shdr->sh_offset);

            /* Iterate through the relocations. */
            for (size_t ii = 0; ii < nrel; ii++) {
                void *reladdr = reldata + ii * rsize;

                switch (shdr->sh_type) {
                case SHT_REL:
                    DEBUG_PRINTF("SHT_REL unimplemented.\n");
                    return ELF_ERR_PROGHDR;
                case SHT_RELA: {
                    struct Elf64_Rela *rel = reladdr;

                    uint64_t offset = rel->r_offset;
                    uint64_t sym = ELF64_R_SYM(rel->r_info);
                    uint64_t type = ELF64_R_TYPE(rel->r_info);
                    uint64_t addend = rel->r_addend;

                    uint64_t *rel_target = (void *)offset + segment_vdelta;

                    switch (type) {
                    case R_AARCH64_RELATIVE:
                        if (sym != 0) {
                            DEBUG_PRINTF("Relocation references a"
                                         " dynamic symbol, which is"
                                         " unsupported.\n");
                            return ELF_ERR_PROGHDR;
                        }

                        /* Delta(S) + A */
                        *rel_target = addend + segment_delta + load_offset;
                        break;

                    default:
                        DEBUG_PRINTF("Unsupported relocation type %d\n", type);
                        return ELF_ERR_PROGHDR;
                    }
                } break;
                default:
                    DEBUG_PRINTF("Unexpected type\n");
                    break;
                }
            }
        }
    }

    return SYS_ERR_OK;
}

static errval_t get_kcb(struct capref *kcb_cap)
{
    // - Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
    //   Note that it should at least OBJSIZE_KCB, and it should also be aligned
    //   to a multiple of 16k.

    errval_t err;
    struct capref ram_cap;
    err = ram_alloc_aligned(&ram_cap, OBJSIZE_KCB, 4 * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can not allocate ramcap for KCB");
        return err;
    }

    err = slot_alloc(kcb_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can not allocate slot for kcb cap\n");
        return err;
    }

    err = cap_retype(*kcb_cap, ram_cap, 0, ObjType_KernelControlBlock, OBJSIZE_KCB, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can not retype KCB cap");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t load_and_relocate_driver(const char *driver, const char *entry_symbol,
                                         lvaddr_t load_offset,
                                         struct mem_info *driver_mem_info,
                                         genpaddr_t *driver_entry)
{
    // - Get and load the CPU and boot driver binary.
    errval_t err;

    DEBUG_PRINTF("Loading module\n");
    struct mem_region *driver_mem_region = multiboot_find_module(bi, driver);
    if (driver_mem_region == NULL) {
        err = SYS_ERR_KCB_NOT_FOUND;
        DEBUG_ERR(err, "Could not find driver module");
        return err;
    }

    DEBUG_PRINTF("Mapping module\n");
    lvaddr_t elf_vaddr;
    size_t elf_size;
    err = spawn_map_module(driver_mem_region, &elf_size, (void *)&elf_vaddr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not map driver module");
        return err;
    }

    DEBUG_PRINTF("Finding entry symbol in ELF binary\n");
    uintptr_t symbol_index = 0;
    struct Elf64_Sym *driver_init_location = elf64_find_symbol_by_name(
        (genvaddr_t)elf_vaddr, elf_size, entry_symbol, 0, STT_FUNC, &symbol_index);
    if (!driver_init_location) {
        err = SYS_ERR_KCB_NOT_FOUND;
        DEBUG_ERR(err, "Failed to find entry symbol in ELF binary");
        return err;
    }

    DEBUG_PRINTF("Allocating frame\n");
    size_t elf_vsize = elf_virtual_size((lvaddr_t)elf_vaddr);
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, elf_vsize, &driver_mem_info->size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated frame");
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    DEBUG_PRINTF("Mapping frame\n");
    err = paging_map_frame(get_current_paging_state(), &driver_mem_info->buf,
                           driver_mem_info->size, frame_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to do page mapping");
        return err_push(err, LIB_ERR_PMAP_MAP);
    }

    DEBUG_PRINTF("Reading frame physical address\n");
    struct capability c;
    err = invoke_cap_identify(frame_cap, &c);
    if (err_is_fail(err)) {
        debug_printf("Failed to get physcal address of cap ref\n");
    }
    driver_mem_info->phys_base = c.u.frame.base;

    DEBUG_PRINTF("Loading ELF binary\n");
    genpaddr_t driver_entry_point;
    err = load_elf_binary((genvaddr_t)elf_vaddr, driver_mem_info,
                          driver_init_location->st_value, &driver_entry_point);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to load driver ELF binary");
        return err;
    }

    // - Relocate the boot and CPU driver. The boot driver runs with a 1:1
    //   VA->PA mapping. The CPU driver is expected to be loaded at the
    //   high virtual address space, at offset ARMV8_KERNEL_OFFSET.
    DEBUG_PRINTF("Relocating ELF binary\n");
    err = relocate_elf((genvaddr_t)elf_vaddr, driver_mem_info, load_offset);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to relocate cpu elf binary");
        return err;
    }

    *driver_entry = driver_entry_point + load_offset;

    return SYS_ERR_OK;
}

__attribute__((__used__)) static errval_t allocate_page_core_data(void)
{
    // - Allocate a page for the core data struct
    return SYS_ERR_OK;
}

__attribute__((__used__)) static errval_t allocate_stack_memory(void)
{
    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    return SYS_ERR_OK;
}

__attribute__((__used__)) static errval_t get_cpu_entrypoint(void)
{
    // - Find the CPU driver entry point. Look for the symbol "arch_init". Put
    //   the address in the core data struct.
    return SYS_ERR_OK;
}

__attribute__((__used__)) static errval_t get_boot_entrypoint(void)
{
    // - Find the boot driver entry point. Look for the symbol "boot_entry_psci"
    return SYS_ERR_OK;
};

__attribute__((__used__)) static errval_t flush_cache(void)
{
    // - Flush the cache.

    // use functions from cache.h
    // if inv means invalidate, then these should be the correct functions:

    /*
    arm64_idcache_wbinv_range();
    arm64_dcache_wbinv_range();
    arm64_dcache_inv_range();
     */
    return SYS_ERR_OK;
}

__attribute__((__used__)) static errval_t spawn_core(hwid_t core_id,
                                                     enum cpu_type cpu_type,
                                                     genpaddr_t entry, genpaddr_t context,
                                                     uint64_t psci_use_hvc)
{
    // - Call the invoke_monitor_spawn_core with the entry point
    //   of the boot driver and pass the (physical, of course) address of the
    //   boot struct as argument.
    errval_t err;
    err = invoke_monitor_spawn_core(core_id, cpu_type, entry, context, psci_use_hvc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn core");
        return err;
    }
    return SYS_ERR_OK;
}

errval_t coreboot(coreid_t mpid, const char *boot_driver, const char *cpu_driver,
                  const char *init, struct frame_identity urpc_frame_id)
{
    // Implement me!
    DEBUG_PRINTF("Inside coreboot!! \n");

    errval_t err;

    struct capref kcb_cap;
    DEBUG_PRINTF("Creating Kernel Control Block\n");
    err = get_kcb(&kcb_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can not fetch KCB cap\n");
        return err;
    }

    DEBUG_PRINTF("Loading boot driver\n");
    struct mem_info boot_driver_mem_info;
    genpaddr_t boot_driver_entry;
    err = load_and_relocate_driver(boot_driver, "boot_entry_psci", 0,
                                   &boot_driver_mem_info, &boot_driver_entry);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to load and relocate the boot driver");
        return err;
    }

    DEBUG_PRINTF("loading cpu driver\n");
    struct mem_info cpu_driver_mem_info;
    genpaddr_t cpu_driver_entry;
    err = load_and_relocate_driver(cpu_driver, "arch_init", ARMv8_KERNEL_OFFSET,
                                   &cpu_driver_mem_info, &cpu_driver_entry);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to load and relocate the cpu driver");
        return err;
    }

    USER_PANIC("there we go");

    // err = allocate_page_core_data();

    // err = allocate_stack_memory();

    // - Fill in the core data struct, for a description, see the definition
    //   in include/target/aarch64/barrelfish_kpi/arm_core_data.h

    /*
    struct armv8_core_data core_data = {
        ARMV8_BOOTMAGIC_PSCI,
    };
     */


    // err = get_cpu_entrypoint();

    // err = get_boot_entrypoint();

    // err = flush_cache();

    // err = spawn_core(hwid_t core_id, CPU_ARM8, genpaddr_t entry, genpaddr_t
    // context, true);
    return SYS_ERR_OK;
}
