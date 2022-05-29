#include <stdio.h>
#include <stdlib.h>

#include "proc_mgmt.h"
#include "init_lmp.h"
#include "init_ump.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/paging.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>

#include <maps/qemu_map.h>
#include <maps/imx8x_map.h>


errval_t process_get_all_pids(size_t *ret_nr_of_pids, domainid_t **ret_pids)
{
    errval_t err = spawn_get_all_pids(ret_nr_of_pids, ret_pids);
    return err;
}

/**
 * @brief Lookup PID on current core and return name of process
 *
 * @param pid Pid to look at
 * @param retname filled with "" if PID not found, else with binary name
 * @return errval_t Error if unexpected error. PID not found is not an error
 */
errval_t process_pid2name(domainid_t pid, char **retname)
{
    // lookup the pid on this core
    struct spawninfo *info;
    errval_t err = spawn_get_process_by_pid(pid, &info);

    if (err_is_fail(err)) {
        if (err == SPAWN_ERR_PID_NOT_FOUND) {
            // doesn't exist!
            *retname = "";
        } else {
            DEBUG_ERR(err, "error when looking for pid in process_pid2name");
            return err;
        }
    }

    *retname = info->binary_name;
    return SYS_ERR_OK;
}

errval_t process_spawn_request(char *cmd, domainid_t *pid)
{
    // malloc into the datastructure; spawn is responsible for freeing again
    struct spawninfo *info = malloc(sizeof(struct spawninfo));
    if (!info) {
        return LIB_ERR_MALLOC_FAIL;
    }
    errval_t err = spawn_process(cmd, info, pid);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to start process over ump: %s\n", cmd);
    }
    return err;
}

static errval_t register_receive_handlers(struct spawninfo *si)
{
    errval_t err;

    // setup handler for the process
    err = aos_lmp_register_recv(&si->lmp, init_process_msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register receive handler");
        return err;
    }
    err = aos_lmp_register_recv(&si->mem_lmp, init_process_msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register memory receive handler");
        return err;
    }

    err = aos_lmp_register_recv(&si->serial_lmp, init_process_msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register serial receive handler");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t setup_process(char *cmd, struct spawninfo *si, domainid_t *pid)
{
    errval_t err;

    err = spawn_setup_by_name(cmd, si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn \"%s\"", cmd);
        return err_push(err, SPAWN_ERR_LOAD);
    }

    return SYS_ERR_OK;
}

errval_t dispatch_process(struct spawninfo *si)
{
    errval_t err;

    err = spawn_invoke_dispatcher(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to dispatch process");
        return err;
    }


    err = register_receive_handlers(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register receive handler for channel to %s in init\n",
                  si->binary_name);
        return err;
    }

    return SYS_ERR_OK;
}

errval_t spawn_process(char *cmd, struct spawninfo *si, domainid_t *pid)
{
    errval_t err;

    err = spawn_load_by_name(cmd, si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn \"%s\"", cmd);
        return err_push(err, SPAWN_ERR_LOAD);
    }

    err = register_receive_handlers(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register receive handler for channel to %s in init\n",
                  cmd);
        return err;
    }

    return SYS_ERR_OK;
}

errval_t process_aos_ump_bind_request(struct capref frame_cap)
{
    errval_t err;
    struct aos_ump *new_chan = malloc(sizeof(struct aos_ump));
    if (!new_chan) {
        DEBUG_PRINTF("Failed to malloc new channel\n");
        err = LIB_ERR_MALLOC_FAIL;
        return err;
    }

    err = aos_ump_create_chan(&frame_cap, new_chan, false, true);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("Could not create channel during UMP binding\n");
        free(new_chan);
        return err_push(LIB_ERR_UMP_CHAN_BIND, err);
    }

    run_ump_listener_thread(new_chan, true);

    return SYS_ERR_OK;
}

errval_t process_write_char_request(char *buf)
{
    errval_t err = sys_print(buf, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error writing to serial");
        return err;
    }
    return SYS_ERR_OK;
}

errval_t process_read_char_request(char *c)
{
    errval_t err = sys_getchar(c);
    if (err_is_fail(err)) {
        return err;
    }
    return SYS_ERR_OK;
}

static errval_t setup_driver_devframe(struct spawninfo *si, gensize_t register_base,
                                      gensize_t register_size, cslot_t slot)
{
    errval_t err;
    struct capref device_cap = (struct capref) {
        .cnode = cnode_task,
        .slot = TASKCN_SLOT_DEV,
    };

    struct capref devframe_cap = (struct capref) {
        .cnode = si->argcn,
        .slot = slot,
    };

    genpaddr_t dev_addr;
    err = get_phys_addr(device_cap, &dev_addr, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get physical address of cap");
    }

    err = cap_retype(devframe_cap, device_cap, register_base - dev_addr, ObjType_DevFrame,
                     register_size, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to retype cap");
    }

    return SYS_ERR_OK;
}

errval_t spawn_lpuart_driver(struct spawninfo **retsi)
{
    errval_t err;

    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    err = setup_process("shell", si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn shell");
    }

    /*
    // NOTE: will only run with IMX8X
    // use to run with board: IMX8X_UART0_BASE, IMX8X_UART_SIZE
    // map capability to access UART device
    err = setup_driver_devframe(si, QEMU_UART_BASE, QEMU_UART_SIZE, ARGCN_SLOT_DEVFRAME);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup driver for (qemu) UART \n");
        return err;
    }

    // map capability to access interrupt handler in user space, which is abstracted as device
    err = setup_driver_devframe(si, QEMU_GIC_DIST_BASE, QEMU_GIC_DIST_SIZE, ARGCN_SLOT_DEVFRAME_IRQ);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup driver for (qemu) UART GIC \n");
        return err;
    }
    */

    err = dispatch_process(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to dispatch process");
        return err;
    }

    if (retsi) {
        *retsi = si;
    }

    return SYS_ERR_OK;
}

errval_t spawn_sdhc_driver(struct spawninfo **retsi)
{
    errval_t err;

    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    err = setup_process("fs", si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn filesystem driver");
    }

    // TODO altin check if thats everything you need
    // NOTE: will only run with IMX8X
    err = setup_driver_devframe(si, IMX8X_SDHC1_BASE, IMX8X_SDHC_SIZE, ARGCN_SLOT_DEVFRAME);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup driver dev frame");
        return err;
    }

    err = dispatch_process(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to dispatch process");
        return err;
    }

    if (retsi) {
        *retsi = si;
    }

    return SYS_ERR_OK;
}

errval_t spawn_enet_driver(struct spawninfo **retsi)
{
    errval_t err;

    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    err = setup_process("enet", si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn network driver");
    }

    // NOTE: will only run with IMX8X
    err = setup_driver_devframe(si, IMX8X_ENET_BASE, IMX8X_ENET_SIZE, ARGCN_SLOT_DEVFRAME);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to setup driver dev frame");
        return err;
    }

    err = dispatch_process(si);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to dispatch process");
        return err;
    }

    if (retsi) {
        *retsi = si;
    }

    return SYS_ERR_OK;
}