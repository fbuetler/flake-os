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
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t spawn_setup_vspace(struct spawninfo *si)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t spawn_load_elf_binary(struct spawninfo *si, lvaddr_t binary,
                                      size_t binary_size, genvaddr_t *entry)
{
    // elf_allocator_fn allocator; // create or find allocator
    // void* elf_state; // create or find struct to store elf state
    // genvaddr_t entry_point; // this is returned from elf_load

    // elf_load(EM_AARCH64, allocator, elf_state, buf, size, entry_point);

    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t spawn_setup_dispatcher(struct spawninfo *si, genvaddr_t entry)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t spawn_setup_env(struct spawninfo *si, char *argv[])
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 *
 * @param state
 * @param base
 * @param size
 * @param flags
 * @param ret Pointer to allocated vspace in current process
 * @return
 */
errval_t allocator_fn(void *state, genvaddr_t base, size_t size, uint32_t flags,
                      void **ret)
{
    printf("allocator_fn called \n");

    errval_t err;

    struct capref segment_frame;
    size_t ret_size;

    err = frame_alloc(&segment_frame, size, &ret_size);

    if (err_is_fail(err)) {
        printf("Could not allocate new frame for segment \n");
        return err;
    }

    printf("Mapping into current vspace \n");
    // map memory into current vspace
    err = paging_map_frame_attr(get_current_paging_state(), ret, size, segment_frame,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        printf("Could not map frame for segment into current vspace \n");
        return err;
    }

    // map memory in child vspace

    printf("Mapping into child vspace \n");
    // flags in elf.h have different values than flags in paging_types.h. PF_X (execute)
    // is 0x01 but VREGION_FLAGS_EXECUTE is 0x04
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

    err = paging_map_frame_attr(get_current_paging_state(), ((void *)base), size,
                                segment_frame, child_flags);
    if (err_is_fail(err)) {
        printf("Could not map frame for segment into child vspace \n");
        return err;
    }

    return SYS_ERR_OK;
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
    assert(*(char *)(binary + 0) == 0x7f);
    assert(*(char *)(binary + 1) == 0x45);
    assert(*(char *)(binary + 2) == 0x4c);
    assert(*(char *)(binary + 3) == 0x46);

    /*
    elf_allocator_fn allocator;
    void* state;
    genvaddr_t entry_addr;

    err = elf_load(EM_AARCH64, &allocator_fn, state, binary, si->module->mrmod_size,
    &entry_addr); assert(err_is_ok(err)); printf("after loading elf");
    */

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
    err = spawn_load_elf_binary(si, binary, binary_size, &entry);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to load ELF binary");
        return err_push(err, SPAWN_ERR_LOAD);
    }

    // setup dispatcher
    err = spawn_setup_dispatcher(si, entry);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup dispatcher");
        return err_push(err, SPAWN_ERR_DISPATCHER_SETUP);
    }

    // setup environment
    err = spawn_setup_env(si, argv);
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
