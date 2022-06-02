#include <stdio.h>
#include <stdlib.h>

#include "init_ump.h"

#include "core_mgmt.h"
#include "proc_mgmt.h"
#include "init_lmp.h"
#include "nameserver/server.h"

#include <serialio/serialio.h>

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <aos/nameserver.h>
#include <spawn/spawn.h>
#include <aos/kernel_cap_invocations.h>
#include <serialio/serialio.h>

static void aos_ump_send_errval_response(struct aos_ump *ump, errval_t err)
{
    struct aos_rpc rpc;
    aos_rpc_init_from_ump(&rpc, ump);
    aos_rpc_send_errval(&rpc, err);
}

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
                aos_ump_send_errval_response(ump, err);
                continue;
            }

            err = aos_ump_send(ump, AosRpcSpawnResponse, (char *)&pid, sizeof(domainid_t));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to respond to spawn request!\n");
                aos_ump_send_errval_response(ump, err);
                continue;
            }

            DEBUG_PRINTF("responded to UmpSpawn\n");
            continue;
        }
        case AosRpcSpawnResponse: {
            DEBUG_PRINTF("launched process; PID is: 0x%lx\n", *(size_t *)payload);

            DEBUG_PRINTF("responded to UmpSpawnResponse\n");
            continue;
        }
        case AosRpcPid2Name: {
            char *name;

            domainid_t pid = *(domainid_t *)payload;
            err = process_pid2name(pid, &name);
            if(err == SPAWN_ERR_PID_NOT_FOUND){
                name = "";
            }else if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to process pid2name request!\n");
                continue;
            }

            err = aos_ump_send(ump, AosRpcPid2NameResponse, name, strlen(name) + 1);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to respond to pid2name request!\n");
                continue;
            }

            //DEBUG_PRINTF("responded to UmpPid2Name\n");
            continue;
        }
        case AosRpcGetAllPids: {
            //DEBUG_PRINTF("got a getallpids request\n");
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
            DEBUG_PRINTF("responded to UmpGetAllPids\n");
            continue;
        }
        case AosRpcCpuOff: {
            err = cpu_off();
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to turn cpu of");
            }
            DEBUG_PRINTF("responded to UmpCpuOff\n");
            continue;
        }
        case AosRpcPing: {
            DEBUG_PRINTF("PING: (%d) %s\n", strlen(payload), payload);
            payload = "pong";
            err = aos_ump_send(ump, AosRpcPong, payload, strlen(payload));
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to send message");
                continue;
            }
            DEBUG_PRINTF("responded to UmpPing\n");
            continue;
        }
        case AosRpcPong: {
            DEBUG_PRINTF("PONG: %s\n", payload);
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

            DEBUG_PRINTF("ump response has been sent\n");

            continue;
        }
        case AosRpcClose: {
            char response_payload[1];
            aos_ump_send(ump, AosRpcCloseReponse, response_payload, 1);
            debug_printf("channel closing...\n");
            return;
        }
        case AosRpcSerialWriteChar: {
            // either sends back a response (if payload[1] == 1),
            // or just prints
            err = serial_put_char(NULL, payload);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to write char to serial\n");
                continue;
            }
            if(len == 1){
                // if request len is 2, we don't send back a response as to 
                // this is used to have huge performance gains
                // however, if len is 1, we send back a response
                // this is so we don't break the protocol
                // defined by aos_ump_call
                char retpayload[1];
                aos_ump_send(ump, AosRpcSerialWriteCharResponse, retpayload, 1);
            }else{
                assert(payload[1] == 1);
            }
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
        case AosRpcNsRegister: {
            err = aos_process_service_register(payload, len);
            free(payload);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Could not register service\n");
            }

            continue;
        }
        case AosRpcNsLookup: {
            service_info_t *info;
            err = aos_process_service_lookup(payload, len, &info);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to process the service lookup message.");
                aos_ump_send_errval_response(ump,
                                             err_push(err, LIB_ERR_NAMESERVICE_REGISTER));
                continue;;
            }

            aos_ump_send(ump, AosRpcNsLookupResponse, (char *)info, service_info_size(info));
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