#include <stdio.h>
#include <stdlib.h>

#include "proc_mgmt.h"
#include "init_rpc.h"
#include "init_ump.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/paging.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>

/**
 * 
 * 
 * @brief Lookup PID on current core and return name of process
 * 
 * @param pid Pid to look at
 * @param retname filled with "" if PID not found, else with binary name
 * @return errval_t Error if unexpected error. PID not found is not an error
 */
errval_t process_pid2name(domainid_t pid, char **retname){
    // lookup the pid on this core
    struct spawninfo *info;
    errval_t err = spawn_get_process_by_pid(pid, &info);

    if(err_is_fail(err)){
        if(err == SPAWN_ERR_PID_NOT_FOUND){
            // doesn't exist!
            *retname = "";
        }else{
            DEBUG_ERR(err, "error when looking for pid in process_pid2name");
            return err;
        }
    }

    *retname = info->binary_name;
    return SYS_ERR_OK;
}

errval_t process_spawn_request(char *cmd, domainid_t *pid){
    // malloc into the datastructure; spawn is responsible for freeing again
    struct spawninfo *info = malloc(sizeof(struct spawninfo));
    errval_t err = start_process(cmd, info, pid); 
    if(err_is_fail(err)){
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
    err = aos_rpc_register_recv(&si->rpc, init_process_msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register receive handler for channel to %s in init\n",
                  cmd);
        return err;
    }

    return SYS_ERR_OK;
}