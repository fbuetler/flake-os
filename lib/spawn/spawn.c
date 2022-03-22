#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <spawn/spawn.h>

#include <elf/elf.h>
#include <aos/dispatcher_arch.h>
#include <aos/lmp_chan.h>
#include <aos/aos_rpc.h>
#include <barrelfish_kpi/paging_arm_v8.h>
#include <barrelfish_kpi/domain_params.h>
#include <spawn/multiboot.h>
#include <spawn/argv.h>

extern struct bootinfo *bi;
extern coreid_t my_core_id;


/**
 * \brief Set the base address of the .got (Global Offset Table) section of the ELF binary
 *
 * \param arch_load_info This must be the base address of the .got section (local to the
 * child's VSpace). Must not be NULL.
 * \param handle The handle for the new dispatcher that is to be spawned. Must not be NULL.
 * \param enabled_area The "resume enabled" register set. Must not be NULL.
 * \param disabled_area The "resume disabled" register set. Must not be NULL.
 */
__attribute__((__used__)) static void
armv8_set_registers(void *arch_load_info, dispatcher_handle_t handle,
                    arch_registers_state_t *enabled_area,
                    arch_registers_state_t *disabled_area)
{
    assert(arch_load_info != NULL);
    uintptr_t got_base = (uintptr_t)arch_load_info;

    struct dispatcher_shared_aarch64 *disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base = got_base;

    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
}

static errval_t spawn_map_module(struct mem_region *module, size_t *retsize,
                                 lvaddr_t *retaddr)
{
    errval_t err;

    void *base;
    size_t module_size = module->mrmod_size;
    struct capref cap_frame = {
        .cnode = cnode_module,
        .slot = module->mrmod_slot,
    };

    err = paging_map_frame_attr(get_current_paging_state(), (void **)&base, module_size,
                                cap_frame, VREGION_FLAGS_READ_EXECUTE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map module frame");
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    if (retsize != NULL) {
        *retsize = module_size;
    }

    if (retaddr != NULL) {
        *retaddr = (lvaddr_t)base;
    }

    return SYS_ERR_OK;
}

static errval_t spawn_setup_cspace(struct spawninfo *si)
{
    errval_t err;

    // create root cnode
    err = cnode_create_l1(&si->rootcn_cap, &si->rootcn);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create root cnode");
        return err_push(err, SPAWN_ERR_CREATE_ROOTCN);
    }

    // create task cnode
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_TASKCN, &si->taskcn);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create task cnode");
        return err_push(err, SPAWN_ERR_CREATE_TASKCN);
    }

    // create slot alloc cnodes
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_SLOT_ALLOC0, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create alloc 0 cnode");
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_SLOT_ALLOC1, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create alloc 1 cnode");
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_SLOT_ALLOC2, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create alloc 2 cnode");
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }

    // create base page cnode
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_BASE_PAGE_CN,
                                  &si->base_pagecn);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create base page cnode");
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }

    // create page cnode
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_PAGECN, &si->pagecn);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create page cnode");
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }

    // create a dispatcher capability AKA process control block
    err = slot_alloc(&si->dispatcher_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate slot in dispatcher cap");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = dispatcher_create(si->dispatcher_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create dispatcher capability");
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER);
    }

    // copy dispatcher to task cn slot
    struct capref dispatcher = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_DISPATCHER,
    };
    err = cap_copy(dispatcher, si->dispatcher_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to copy dispatcher");
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    // setup endpoint to itself
    struct capref selfep = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_SELFEP,
    };
    err = cap_retype(selfep, dispatcher, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to retype self endpoint");
        return err_push(err, SPAWN_ERR_CREATE_SELFEP);
    }

    // map root L1 cnode
    struct capref rootcn = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_ROOTCN,
    };
    err = cap_copy(rootcn, si->rootcn_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to copy root cn");
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_setup_vspace(struct spawninfo *si)
{
    errval_t err;

    // create new top level page table
    struct capref child_l0_pt = {
        .cnode = si->pagecn,
        .slot = 0,
    };
    err = vnode_create(child_l0_pt, ObjType_VNode_AARCH64_l0);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create vnode l0");
        return err_push(err, LIB_ERR_VNODE_CREATE);
    }

    // copy top level page table from child c space to parent c space to invoke it
    struct capref parent_l0_pt;
    err = slot_alloc(&parent_l0_pt);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate slot for parent l0 page table");
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = cap_copy(parent_l0_pt, child_l0_pt);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to copy child l0 page table");
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    // init paging state
    err = paging_init_state_foreign(&si->paging_state, VADDR_OFFSET, parent_l0_pt,
                                    get_default_slot_allocator());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init foreign paging state");
        return err_push(err, SPAWN_ERR_VSPACE_INIT);
    }


    // allocate RAM cap of BASE_PAGE_SIZE for each slot of BASE_PAGE_CN
    for (int i = 0; i < L2_CNODE_SLOTS; i++) {
        // allocate ram cap into slot 0
        struct capref tmp_ram_cap;
        err = ram_alloc(&tmp_ram_cap, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to allocate ram cap");
            return err_push(err, LIB_ERR_RAM_ALLOC);
        }

        // copy ram cap to right slot
        struct capref ram_cap = (struct capref) {
            .cnode = si->base_pagecn,
            .slot = i,
        };
        err = cap_copy(ram_cap, tmp_ram_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to copy ram cap");
            return err_push(err, LIB_ERR_CAP_COPY);
        }
    }


    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 *
 * @param state
 * @param base region base address of the child process
 * @param size region size of the child process
 * @param flags region flags (bitmask describing the rights) of the child process
 * @param ret pointer to allocated vspace in child process
 * @return
 */
static errval_t elf_allocate(void *state, genvaddr_t base, size_t size, uint32_t flags,
                             void **ret)
{
    printf("allocator_fn called \n");
    errval_t err;

    struct paging_state *paging_state = (struct paging_state *)state;

    struct capref segment_frame;
    size_t allocated_frame_size;
    err = frame_alloc(&segment_frame, size, &allocated_frame_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate new segemtn frame");
        return err_push(err, ELF_ERR_ALLOCATE);
    }

    printf("Mapping into parent vspace \n");
    // map memory into parent vspace
    err = paging_map_frame_attr(get_current_paging_state(), ret, allocated_frame_size,
                                segment_frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map segment frame into parent vspace");
        return err_push(err, ELF_ERR_ALLOCATE);
    }

    // map memory in child vspace
    printf("Mapping into child vspace \n");
    // flags in elf.h have different values than flags in paging_types.h.
    // e.g.: PF_X (execute) is 0x01 but VREGION_FLAGS_EXECUTE is 0x04
    int child_flags = 0;
    if (flags & PF_X) {
        child_flags |= VREGION_FLAGS_EXECUTE;
    }
    if (flags & PF_W) {
        child_flags |= VREGION_FLAGS_WRITE;
    }
    if (flags & PF_R) {
        child_flags |= VREGION_FLAGS_READ;
    }
    err = paging_map_frame_attr(paging_state, ((void *)base), allocated_frame_size,
                                segment_frame, child_flags);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map segment frame into child vspace");
        return err_push(err, ELF_ERR_ALLOCATE);
    }

    return SYS_ERR_OK;
}

/**
 * @brief parses the ELF binary and loads the segements into memory
 *
 * @param si
 * @param binary the binary to be loaded
 * @param binary_size the size of the binary
 * @param entry will be filled with the entry point of the child process
 * @param got_section_base_addr address of the global offset table base address in the
 * child process
 * @return errval_t
 */
static errval_t spawn_load_elf_binary(struct spawninfo *si, lvaddr_t binary,
                                      size_t binary_size, genvaddr_t *entry,
                                      void **got_section_base_addr)
{
    errval_t err;

    err = elf_load(EM_AARCH64, elf_allocate, &si->paging_state, binary, binary_size,
                   entry);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to load elf");
        return err_push(err, SPAWN_ERR_LOAD);
    }

    struct Elf64_Shdr *got_section_header = elf64_find_section_header_name(
        (genvaddr_t)si->module, binary_size, ".got");
    if (!got_section_header) {
        DEBUG_PRINTF("Error trying to fetch global offset table header from elf\n");
        return SPAWN_ERR_LOAD;
    }
    *got_section_base_addr = (void *)got_section_header->sh_addr;

    return SYS_ERR_OK;
}

static errval_t spawn_setup_dispatcher(struct spawninfo *si, genvaddr_t entry,
                                       void *got_section_base_addr)
{
    errval_t err;

    // setup dispatcher frame
    si->dispatcher_frame_cap = (struct capref) {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_DISPFRAME,
    };
    err = frame_create(si->dispatcher_frame_cap, DISPATCHER_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create dispatcher frame");
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER_FRAME);
    }

    // map dispatcher frame into parent process
    void *dispatcher_frame_addr_parent;
    err = paging_map_frame_attr(get_current_paging_state(), &dispatcher_frame_addr_parent,
                                DISPATCHER_FRAME_SIZE, si->dispatcher_frame_cap,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map dispatcher frame into parents vspace");
        return err_push(err, SPAWN_ERR_MAP_DISPATCHER_TO_SELF);
    }

    // map dispatcher frame into child process
    // TODO or use paging_map_fixed_attr() with fixed address
    void *dispatcher_frame_addr_child;
    err = paging_map_frame_attr(&si->paging_state, &dispatcher_frame_addr_child,
                                DISPATCHER_FRAME_SIZE, si->dispatcher_frame_cap,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map dispatcher frame into childs vspace");
        return err_push(err, SPAWN_ERR_MAP_DISPATCHER_TO_NEW);
    }

    // access the dispatcher fields
    si->dispatcher_handle = (dispatcher_handle_t)dispatcher_frame_addr_parent;
    struct dispatcher_shared_generic *disp = get_dispatcher_shared_generic(
        si->dispatcher_handle);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(si->dispatcher_handle);
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(
        si->dispatcher_handle);
    arch_registers_state_t *disbaled_area = dispatcher_get_disabled_save_area(
        si->dispatcher_handle);

    // put initial information in the dispatcher frame

    // core id of the child process
    disp_gen->core_id = disp_get_core_id();
    // virtual addres of the dispatcher frame in the childs vspace
    disp->udisp = (dispatcher_handle_t)dispatcher_frame_addr_child;
    // start child process in disabled mode
    disp->disabled = 1;
    // process name for debugging purposes
    strncpy(disp->name, si->binary_name, DISP_NAME_LEN);
    // set program counter
    disbaled_area->named.pc = entry;

    // initialize offset register
    armv8_set_registers(got_section_base_addr, si->dispatcher_handle, enabled_area,
                        disbaled_area);

    // dont use error handling frames
    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_hdr_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;

    return SYS_ERR_OK;
}

static errval_t spawn_setup_env(struct spawninfo *si, int argc, char *argv[])
{
    errval_t err;

    // setup command line arguments
    si->args_frame_cap = (struct capref) {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_ARGSPAGE,
    };
    err = frame_create(si->args_frame_cap, ARGS_SIZE, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create cli arguments frame");
        return err_push(err, SPAWN_ERR_CREATE_ARGSPG);
    }

    // childs startup code expects everything that does not explicitly
    // have to be filled in by init to be zeroed
    memset(&si->args_frame_cap, 0, sizeof(si->args_frame_cap));

    // map args frame into parents vspace
    void *args_frame_addr_parent;
    err = paging_map_frame_attr(get_current_paging_state(), &args_frame_addr_parent,
                                ARGS_SIZE, si->args_frame_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map args frame into parents vspace");
        return err_push(err, SPAWN_ERR_MAP_ARGSPG_TO_SELF);
    }

    // map args frame into childs vspace
    // TODO or use paging_map_fixed_attr() with fixed address
    void *args_frame_addr_child;
    err = paging_map_frame_attr(&si->paging_state, &args_frame_addr_child, ARGS_SIZE,
                                si->args_frame_cap, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map args frame into childs vspace");
        return err_push(err, SPAWN_ERR_MAP_ARGSPG_TO_NEW);
    }

    /*
        arguments page layout:
        * struct spawn_domain_params
        * command line args
        * env vars
        * NULL pointer to signify the end of the list
    */
    // put args into arguments frame
    // put envs into arguments frame

    // register for the first argument in the enabled save area contains a pointer
    // to the struct spawn_domain_params
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(
        si->dispatcher_handle);
    registers_set_param(enabled_area, (uint64_t)args_frame_addr_child);

    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher called 'argv[0]' with 'argc' arguments.
 *
 * This function spawns a new dispatcher running the ELF binary called
 * 'argv[0]' with 'argc' - 1 additional arguments. It fills out 'si'
 * and 'pid'.
 *
 * \param argc The number of command line arguments. Must be > 0.
 * \param argv An array storing 'argc' command line arguments.
 * \param si A pointer to the spawninfo struct representing
 * the child. It will be filled out by this function. Must not be NULL.
 * \param pid A pointer to a domainid_t variable that will be
 * assigned to by this function. Must not be NULL.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid)
{
    // TODO: Implement me
    // - Initialize the spawn_info struct
    // - Get the module from the multiboot image
    //   and map it (take a look at multiboot.c)
    // - Setup the child's cspace
    // - Setup the child's vspace
    // - Load the ELF binary
    // - Setup the dispatcher
    // - Setup the environment
    // - Make the new dispatcher runnable

    errval_t err;

    // map multiboot image to virtual memory
    lvaddr_t binary;
    size_t binary_size;
    err = spawn_map_module(si->module, &binary_size, &binary);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map module");
        return err;
    }
    // ELF magic number: 0x7f E L F
    printf("%x %c %c %c \n", *(char *)binary, *(char *)(binary + 1),
           *(char *)(binary + 2), *(char *)(binary + 3));
    assert(*(char *)(binary + 0) == 0x7f);
    assert(*(char *)(binary + 1) == 0x45);
    assert(*(char *)(binary + 2) == 0x4c);
    assert(*(char *)(binary + 3) == 0x46);

    // setup cspace
    err = spawn_setup_cspace(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup cspace");
        return err_push(err, SPAWN_ERR_SETUP_CSPACE);
    }

    // setup vspace
    err = spawn_setup_vspace(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup vspace");
        return err_push(err, SPAWN_ERR_VSPACE_INIT);
    }

    // load elf binary
    genvaddr_t entry;
    void *got_section_base_addr;
    err = spawn_load_elf_binary(si, binary, binary_size, &entry, &got_section_base_addr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to load ELF binary");
        return err_push(err, SPAWN_ERR_LOAD);
    }

    // setup dispatcher
    err = spawn_setup_dispatcher(si, entry, got_section_base_addr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup dispatcher");
        return err_push(err, SPAWN_ERR_DISPATCHER_SETUP);
    }

    // setup environment
    err = spawn_setup_env(si, argc, argv);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup environment");
        return err_push(err, SPAWN_ERR_SETUP_ENV);
    }

    /*
     - run the dispatcher
     Make the new dispatcher runnable
     invoke_dispatcher()
     */
    return SYS_ERR_OK;
}


/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher executing 'binary_name'
 *
 * \param binary_name The name of the binary.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 *
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid)
{
    // TODO: Implement me
    // - Get the mem_region from the multiboot image
    // - Fill in argc/argv from the multiboot command line
    // - Call spawn_load_argv

    errval_t err;
    printf("Inside spawn load by name \n");

    // Fill in binary name here as it's (probably) not available in spawn_load_argv anymore
    si->binary_name = binary_name;

    // get memory region from multiboot image
    struct mem_region *module_location;
    module_location = multiboot_find_module(bi, binary_name);
    if (module_location == NULL) {
        debug_printf("Spawn dispatcher: failed to find module location\n");
        return SPAWN_ERR_FIND_MODULE;
    }

    si->module = module_location;

    printf("Successful found multiboot module. Base: %lu size: %lu type: %d mrmod base: "
           "%td mrmod size: %zu\n",
           si->module->mr_base, si->module->mr_bytes, si->module->mr_type,
           si->module->mrmod_data, si->module->mrmod_size);

    // get argc/argv from multiboot command line
    const char *cmd_opts = multiboot_module_opts(module_location);
    if (cmd_opts == NULL) {
        debug_printf("Spawn dispatcher: failed to load arguments\n");
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }
    int argc;
    char *argv_str;  // argv_str stores the raw string of the arguments
    // argv stores an array of argument
    char **argv = make_argv(cmd_opts, &argc, &argv_str);
    if (argv == NULL) {
        debug_printf("Spawn dispatcher: failed to make argv\n");
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }

    // spawn multiboot image
    err = spawn_load_argv(argc, argv, si, pid);
    if (err_is_fail(err)) {
        debug_printf("Spawn dispatcher: failed to spawn a new dispatcher\n");
        return err;
    }

    return SYS_ERR_OK;
}
