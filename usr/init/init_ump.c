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
    ump_msg_type type;
    char *payload;
    size_t len;
    while (1) {
        errval_t err = ump_receive(chan, &type, &payload, &len);
        // debug_printf("received message of type: %d\n", type);
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
                continue;
            }

            debug_printf("responded to UmpSpawn\n");
            continue;
        }
        case UmpSpawnResponse: {
            DEBUG_PRINTF("launched process; PID is: 0x%lx\n", *(size_t *)payload);

            debug_printf("responded to UmpSpawnResponse\n");
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
                continue;
            }

            debug_printf("responded to UmpPid2Name\n");
            continue;
        }
        case UmpGetAllPids: {
            DEBUG_PRINTF("got a getallpids request\n");
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
                continue;
            }
            debug_printf("responded to UmpGetAllPids\n");
            continue;
        }
        case UmpCpuOff: {
            err = cpu_off();
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to turn cpu of");
            }
            debug_printf("responded to UmpCpuOff\n");
            continue;
        }
        case UmpPing: {
            debug_printf("PING: size %d - %s\n", strlen(payload), payload);

            payload = "pong";
            ump_send(chan, UmpPong, payload, strlen(payload));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to send message");
                continue;
            }

            debug_printf("responded to UmpPong\n");
            continue;
        }
        case UmpPong: {
            debug_printf("PONG: %s\n", payload);
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