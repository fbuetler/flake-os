#include <stdio.h>
#include <stdlib.h>

#include "init_ump.h"

#include "core_mgmt.h"
#include "proc_mgmt.h"
#include "init_lmp.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/kernel_cap_invocations.h>

void aos_ump_receive_listener(struct aos_ump *ump)
{
    aos_rpc_msg_type_t type;
    char *payload;
    size_t len;
    while (1) {
        errval_t err = aos_ump_receive(ump, &type, &payload, &len);
        // debug_printf("received message of type: %d\n", type);
        if (err_is_fail(err)) {
            assert(!"couldn't receive ump message in receive listener\n");
        }

        switch (type) {
        case AosRpcSpawnRequest: {
            char *cmd = payload;
            domainid_t pid = 0;
            err = process_spawn_request(cmd, &pid);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to start process over ump: %s\n", cmd);
                continue;
            }

            err = aos_ump_send(ump, AosRpcSpawnResponse, (char *)&pid, sizeof(domainid_t));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to respond to spawn request!\n");
                continue;
            }

            debug_printf("responded to UmpSpawn\n");
            continue;
        }
        case AosRpcSpawnResponse: {
            DEBUG_PRINTF("launched process; PID is: 0x%lx\n", *(size_t *)payload);

            debug_printf("responded to UmpSpawnResponse\n");
            continue;
        }
        case AosRpcPid2Name: {
            char *name;

            domainid_t pid = *(domainid_t *)payload;
            err = process_pid2name(pid, &name);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to process pid2name request!\n");
                continue;
            }

            err = aos_ump_send(ump, AosRpcPid2NameResponse, name, strlen(name) + 1);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to respond to pid2name request!\n");
                continue;
            }

            debug_printf("responded to UmpPid2Name\n");
            continue;
        }
        case AosRpcGetAllPids: {
            DEBUG_PRINTF("got a getallpids request\n");
            size_t nr_of_pids;
            domainid_t *pids;
            err = process_get_all_pids(&nr_of_pids, &pids);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to get all pids!\n");
                continue;
            }

            err = aos_ump_send(ump, AosRpcGetAllPidsResponse, (char *)pids,
                               nr_of_pids * sizeof(domainid_t));
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to respond to get all pids!\n");
                continue;
            }
            debug_printf("responded to UmpGetAllPids\n");
            continue;
        }
        case AosRpcCpuOff: {
            err = cpu_off();
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to turn cpu of");
            }
            debug_printf("responded to UmpCpuOff\n");
            continue;
        }
        case AosRpcPing: {
            payload = "pong";
            err = aos_ump_send(ump, AosRpcPong, payload, strlen(payload));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to send message");
                continue;
            }
            debug_printf("responded to UmpPing\n");
            continue;
        }
        case AosRpcPong: {
            debug_printf("PONG: %s\n", payload);
            continue;
        }
        case AosRpcBind: {
            DEBUG_PRINTF("received remote UMP Bind request\n");

            // extract memory region
            genpaddr_t base = *(genpaddr_t *)payload;
            gensize_t size = *(gensize_t *)(payload + sizeof(genpaddr_t));

            struct capref mem_cap;
            err = slot_alloc(&mem_cap);

            if (err_is_fail(err)) {
                DEBUG_PRINTF("Could not allocate slot for ramp cap during UMP binding\n");
                // return err_push(LIB_ERR_UMP_CHAN_BIND, err);;
                continue;
            }

            err = frame_forge(mem_cap, base, size, disp_get_current_core_id());
            if (err_is_fail(err)) {
                DEBUG_PRINTF("Could not forge shared frame during UMP binding\n");
                // return err_push(LIB_ERR_UMP_CHAN_BIND, err);
                continue;
            }

            process_aos_ump_bind_request(mem_cap);

            // TODO: is problem fixed that we can't send payloads of size 0?
            char response_payload[1];
            aos_ump_send(ump, AosRpcBindReponse, response_payload, 1);

            debug_printf("ump response has been sent\n");

            continue;
        }
        case AosRpcClose: {
            char response_payload[1];
            aos_ump_send(ump, AosRpcCloseReponse, response_payload, 1);
            debug_printf("channel closing...\n");
            return;
        }
        case AosRpcSerialWriteChar: {
            err = process_write_char_request((char *)payload);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to write char to serial\n");
                continue;
            }
            char retpayload[1];
            aos_ump_send(ump, AosRpcSerialWriteCharResponse, retpayload, 1);
            continue;
        }
        case AosRpcSerialReadChar: {
            char retpayload[1];
            err = process_read_char_request(retpayload);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Could not read char in UMP \n");
                continue;
            }
            aos_ump_send(ump, AosRpcSerialReadCharResponse, retpayload, 1);
            continue;
        }
        default: {
            assert(!"unknown type message received in ump receive listener\n");
            return;
        }
        }
    }
}

int aos_ump_receive_listener_thread_func(void *arg)
{
    struct aos_ump *chan = (struct aos_ump *)arg;

    aos_ump_receive_listener(chan);
    return 0;
}

int aos_ump_receive_listener_thread_func_malloced(void *arg)
{
    aos_ump_receive_listener_thread_func(arg);

    free(arg);
    DEBUG_PRINTF("malloced UMP channel has been freed\n");

    return 0;
}

struct thread *run_ump_listener_thread(struct aos_ump *ump, bool is_malloced)
{
    struct thread *t;
    if (!is_malloced) {
        t = thread_create(aos_ump_receive_listener_thread_func, (void *)ump);
    } else {
        t = thread_create(aos_ump_receive_listener_thread_func_malloced, (void *)ump);
    }
    return t;
}