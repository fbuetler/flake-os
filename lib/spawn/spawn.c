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
                                      size_t binary_size, genvaddr_t entry)
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
    err = spawn_map_module(si->mem_region, &binary_size, &binary);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map module");
        return err;
    }
    // ELF magic number: 0x7f E L F
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

    si->mem_region = module_location;

    printf("Successful found multiboot module. Base: %lu size: %lu type: %d mrmod base: "
           "%td mrmod size: %zu\n",
           si->mem_region->mr_base, si->mem_region->mr_bytes, si->mem_region->mr_type,
           si->mem_region->mrmod_data, si->mem_region->mrmod_size);

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
