#include <stdio.h>
#include <stdlib.h>

#include "init_ump.h"

#include "core_mgmt.h"
#include "proc_mgmt.h"
#include "init_rpc.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>

void ump_receive_listener(struct ump_chan *chan)
{
    enum ump_msg_type type;
    char *payload;
    size_t len;
    while (1) {
        errval_t err = ump_receive(chan, &type, &payload, &len);
        if (err_is_fail(err)) {
            assert(!"couldn't receive ump message in receive listener\n");
        }

        switch (type) {
        case UmpSpawn: {
            char *cmd = payload;
            domainid_t pid = 0;
            err = process_spawn_request(cmd, &pid);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to start process over ump: %s\n", cmd);
                continue;
            }

            err = ump_send(chan, UmpSpawnResponse, (char *)&pid, sizeof(domainid_t));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to respond to spawn request!\n");
            }
            continue;
        }
        case UmpSpawnResponse: {
            DEBUG_PRINTF("launched process; PID is: 0x%lx\n", *(size_t *)payload);
            continue;
        }
        case UmpPid2Name: {
            char *name;

            domainid_t pid = *(domainid_t *)payload;
            err = process_pid2name(pid, &name);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to process pid2name request!\n");
                continue;
            }

            err = ump_send(chan, UmpPid2NameResponse, name, strlen(name) + 1);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to respond to pid2name request!\n");
            }
            continue;
        }
        case UmpGetAllPids: {
            debug_printf("got a getallpids request\n");
            size_t nr_of_pids;
            domainid_t *pids;
            err = process_get_all_pids(&nr_of_pids, &pids);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to get all pids!\n");
                continue;
            }

            err = ump_send(chan, UmpGetAllPidsResponse, (char *)pids,
                           nr_of_pids * sizeof(domainid_t));
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to respond to get all pids!\n");
            }
            continue;
        }
        case UmpCpuOff: {
            err = cpu_off();
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to turn cpu of");
            }
            continue;
        }
        default: {
            assert(!"unknown type message received in ump receive listener\n");
            return;
        }
        }
    }
}

int ump_receive_listener_thread_func(void *arg)
{
    struct ump_chan *chan = (struct ump_chan *)arg;

    ump_receive_listener(chan);

    return 0;
}

struct thread *run_ump_listener_thread(void)
{
    struct ump_chan *chan = &ump_chans[!disp_get_core_id()];
    struct thread *t = thread_create(ump_receive_listener_thread_func, (void *)chan);
    return t;
}