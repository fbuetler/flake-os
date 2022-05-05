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
    errval_t err = start_process(cmd, info, pid);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to start process over ump: %s\n", cmd);
    }
    return err;
}

errval_t start_process(char *cmd, struct spawninfo *si, domainid_t *pid)
{
    errval_t err;

    err = spawn_load_by_name(cmd, si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn \"%s\"", cmd);
        return err_push(err, SPAWN_ERR_LOAD);
    }

    // setup handler for the process
    err = aos_lmp_register_recv(&si->lmp, init_process_msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register receive handler for channel to %s in init\n",
                  cmd);
        return err;
    }
    err = aos_lmp_register_recv(&si->mem_lmp, init_process_msg);
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