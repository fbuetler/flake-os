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