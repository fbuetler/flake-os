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


    // - initialize spawn_info struct

    // - map multiboot image to virtual memory

    // allocate virtual memory
    void *buf;
    size_t size = si->module->mrmod_size;  // mr_bytes is empty so mrmod_size is correct
    int flag = VREGION_FLAGS_READ; // Not sure which flag is required


    // capref from book page 83
    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = si->module->mrmod_slot,
    };

    printf("before paging map frame \n");

    paging_map_frame_attr(get_current_paging_state(), &buf, size, child_frame, flag);

    printf("after paging map frame \n");

    printf("%x %c %c %c \n", *(char *)buf, *(char *)(buf + 1), *(char *)(buf + 2),
           *(char *)(buf + 3));
    assert(*(char *)(buf + 1) == 0x45);
    assert(*(char *)(buf + 2) == 0x4c);
    assert(*(char *)(buf + 3) == 0x46);

    printf("ELF magic header is correct :) \n");

    // - setup cspace

    // - setup vspace
    /*
    // - load elf binary
    elf_allocator_fn allocator; // create or find allocator
    void* elf_state; // create or find struct to store elf state
    genvaddr_t entry_point; // this is returned from elf_load

    elf_load(EM_AARCH64, allocator, elf_state, buf, size, entry_point);

    // - setup dispatcher

    // - setup environment

    // - run the dispatcher
    // invoke_dispatcher()
     */
    elf_load()
    return LIB_ERR_NOT_IMPLEMENTED;
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

    printf("Inside spawn load by name \n");

    // Fill in binary name here as it's (probably) not available in spawn_load_argv anymore
    si->binary_name = binary_name;

    // - get memory region from multiboot image

    errval_t err;
    struct mem_region *module_location;
    module_location = multiboot_find_module(bi, binary_name);

    // ToDo: fails because "paging_map_frame_attr()" is not yet implemented
    if (!module_location) {
        printf("ERROR MODULE LOCATION NULL \n");
        return SPAWN_ERR_FIND_MODULE;
    }

    si->module = module_location;

    printf("Successful found multiboot module. Base: %lu size: %lu type: %d mrmod base: "
           "%td mrmod size: %zu\n",
           si->module->mr_base, si->module->mr_bytes, si->module->mr_type,
           si->module->mrmod_data, si->module->mrmod_size);

    // - get argc/argv from multiboot command line

    const char *cmd_opts = multiboot_module_opts(module_location);
    int argc;
    char *buf;  // not sure what the difference between argv and buf is
    char **argv = make_argv(cmd_opts, &argc, &buf);

    if (argv == NULL) {
        printf("ERROR making argv! \n");
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }


    // - spawn multiboot image

    err = spawn_load_argv(argc, argv, si, pid);

    if (!err_is_ok(err)) {
        printf("Error spawning with argv \n");
        return err;
    }

    return SYS_ERR_OK;
}
