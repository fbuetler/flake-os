/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/deferred.h>

static struct aos_rpc *init_rpc;

int main(int argc, char *argv[])
{
    errval_t err = SYS_ERR_OK;

    DEBUG_PRINTF("demom5 started....\n");

    init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        USER_PANIC_ERR(err, "init RPC channel NULL?\n");
    }

    for(int iter = 0; iter < 2; iter++){
        DEBUG_PRINTF("spawning hello\n");
        domainid_t pid;
        err = aos_rpc_process_spawn(init_rpc, "hello", iter, &pid);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "could not spawn process\n");
        }
        

        DEBUG_PRINTF("attempting pid2name...\n");
        char *name;
        aos_rpc_process_get_name(init_rpc, pid, &name);
        DEBUG_PRINTF("received pid2name result of pid 0x%lx: %s\n", pid, name);

        size_t pid_count;
        domainid_t *pids;
        aos_rpc_process_get_all_pids(init_rpc, &pids, &pid_count);

        DEBUG_PRINTF("PID count: %d\n", pid_count);
        
        for(int i = 0; i < pid_count; i++){
            DEBUG_PRINTF("received pid: 0x%lx\n", pids[i]);
        }
    }

    return EXIT_SUCCESS;
}