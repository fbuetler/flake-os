#include <stdio.h>
#include <stdlib.h>

#include "init_rpc.h"

#include "proc_mgmt.h"
#include "init_ump.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/paging.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>
#include <grading.h>


void aos_process_ram_cap_request(struct aos_rpc *rpc)
{
    errval_t err;

    // read ram request properties
    size_t bytes = ((size_t *)rpc->recv_msg->payload)[0];
    size_t alignment = ((size_t *)rpc->recv_msg->payload)[1];

    // grading call
    grading_rpc_handler_ram_cap(bytes, alignment);

    // alloc ram
    struct capref ram_cap;
    err = ram_alloc_aligned(&ram_cap, bytes, alignment);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ram_alloc in ram cap request failed");
        return;
    }

    err = lmp_chan_alloc_recv_slot(&rpc->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        abort();
    }

    // create response with ram cap
    size_t payload_size = 0;
    struct aos_rpc_msg *reply;
    char buf[sizeof(struct aos_rpc_msg)];
    err = aos_rpc_create_msg_no_pagefault(&reply, AosRpcRamCapResponse, payload_size, NULL,
                                          ram_cap, (struct aos_rpc_msg *)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return;
    }

    // char buf1[256];
    // debug_print_cap_at_capref(buf1, 256, ram_cap);
    // DEBUG_PRINTF("%.*s\n", 256, buf1);

    // send response
    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error sending ram cap response\n");
    }
}

void aos_process_spawn_request(struct aos_rpc *rpc)
{
    errval_t err;

    coreid_t *destination_core_ptr = (coreid_t *)rpc->recv_msg->payload;
    coreid_t destination_core = *destination_core_ptr;

    char *module = (char *)(destination_core_ptr + 1);

    // grading
    grading_rpc_handler_process_spawn(module, destination_core);

    domainid_t pid = 0;

    if (destination_core != disp_get_core_id()) {
        // send UMP request to destination core; spawn process there
        DEBUG_PRINTF("destination_core: %d\n", destination_core);
        struct ump_chan *ump = &ump_client_chans[destination_core];


        thread_mutex_lock(&ump->chan_lock);
        err = ump_send(ump, UmpSpawn, module, strlen(module));
        assert(err_is_ok(err));

        // get response!
        ump_msg_type type;
        char *payload;
        size_t len;
        err = ump_receive(ump, &type, &payload, &len);
        thread_mutex_unlock(&ump->chan_lock);

        assert(err_is_ok(err));
        DEBUG_PRINTF("Recieved ump type: %d\n", type);
        assert(type == UmpSpawnResponse);

        pid = *(domainid_t *)payload;
        DEBUG_PRINTF("launched process; PID is: 0x%lx\n", *(size_t *)payload);

    } else {
        err = process_spawn_request(module, &pid);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to start spawn process");
            return;
        }
        DEBUG_PRINTF("spawned process with PID 0x%lx\n", pid);
    }

    size_t payload_size = sizeof(domainid_t);
    void *payload = malloc(payload_size);
    *((domainid_t *)payload) = pid;

    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, AosRpcSpawnResponse, payload_size, (void *)payload,
                             NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return;
    }

    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error sending spawn response\n");
        return;
    }
}

errval_t aos_process_serial_write_char(struct aos_rpc *rpc)
{
    errval_t err;
    if(disp_get_current_core_id() != 0){
        // send to serial driver on core 0
        ump_send(&ump_client_chans[0], UmpSerialWriteChar, rpc->recv_msg->payload, 1);

        ump_msg_type rtype;
        char *rpayload;
        size_t rlen;
        ump_receive(&ump_client_chans[0], &rtype, &rpayload, &rlen);
        assert(rtype == UmpSerialWriteCharResponse);
    }else{
        err = process_write_char_request(rpc->recv_msg->payload);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "failed to writechar");
            return err;
        }
        // grading
        grading_rpc_handler_serial_putchar(*rpc->recv_msg->payload);
    }

    size_t payload_size = 0;
    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, AosRpcSerialWriteCharResponse, payload_size, NULL,
                             NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error sending serial read char response\n");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_process_serial_read_char_request(struct aos_rpc *rpc)
{
    // grading
    grading_rpc_handler_serial_getchar();

    errval_t err;


    char c;
    if(disp_get_current_core_id() != 0){
        // send to serial driver on core 0
        ump_send(&ump_client_chans[0], UmpSerialReadChar, rpc->recv_msg->payload, 1);
        ump_msg_type rtype;
        char *rpayload;
        size_t rlen;
        ump_receive(&ump_client_chans[0], &rtype, &rpayload, &rlen);
        assert(rtype == UmpSerialReadCharResponse);

        c = *rpayload;

    }else{
        err = process_read_char_request(&c);
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to read char on core 0 \n");
            return err;
        }
    } 


    size_t payload_size = sizeof(char);
    void *payload = malloc(payload_size);
    *((char *)payload) = c;

    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, AosRpcSerialReadCharResponse, payload_size, payload,
                             NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error sending serial read char response\n");
        return err;
    }

    return SYS_ERR_OK;
}

static void aos_process_pid2name_request(struct aos_rpc *rpc)
{
    errval_t err;

    domainid_t pid = *((domainid_t *)rpc->recv_msg->payload);

    // grading
    grading_rpc_handler_process_get_name(pid);

    // get destination core
    coreid_t destination_core = pid >> PID_RANGE_BITS_PER_CORE;

    char *name = "";
    if (destination_core != disp_get_core_id()) {
        // process via UMP at destination core
        // TODO here, always 0 or 1 currently
        struct ump_chan *ump = &ump_client_chans[!disp_get_core_id()];

        thread_mutex_lock(&ump->chan_lock);

        err = ump_send(ump, UmpPid2Name, (void *)rpc->recv_msg->payload,
                       sizeof(domainid_t));
        if (err_is_fail(err)) {
            assert(!"couldn't send ump message for pid2name request");
        }

        // receive response
        ump_msg_type type;
        char *payload;
        size_t retsize;
        ump_receive(ump, &type, &payload, &retsize);

        thread_mutex_unlock(&ump->chan_lock);

        if (err_is_fail(err)) {
            assert(!"couldn't send ump message for pid2name request");
        }

        if (*payload != 0) {
            name = payload;
        }

    } else {
        err = process_pid2name(pid, &name);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed pid2name\n");
            assert(!"local pid2name lookup failed");
        }
        debug_printf("local pid2name returned name for pid 0x%lx: %s\n", pid, name);
    }

    // return the name
    size_t payload_size = strlen(name) + 1;

    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, AosRpcPid2NameResponse, payload_size, (void *)name,
                             NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        assert(0);
        return;
    }

    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error sending spawn response\n");
        return;
    }
}

__attribute__((unused)) static errval_t aos_get_remote_pids(size_t *num_pids,
                                                            domainid_t **pids)
{
    // get pids from other core
    DEBUG_PRINTF("getting remote pids...\n");
    struct ump_chan *ump = &ump_client_chans[!disp_get_core_id()];

    thread_mutex_lock(&ump->chan_lock);
    errval_t err = ump_send(ump, UmpGetAllPids, "", 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send UMP message for get all pids");
        return err;
    }

    debug_printf("awaiting remote pids...\n");

    ump_msg_type type;
    char *payload;
    size_t retsize;

    err = ump_receive(ump, &type, &payload, &retsize);

    thread_mutex_unlock(&ump->chan_lock);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not receive UMP message for get all pids");
        return err;
    }

    *pids = (domainid_t *)payload;
    *num_pids = retsize / sizeof(domainid_t);

    return SYS_ERR_OK;
}

static errval_t aos_process_ump_bind_request(struct aos_rpc *rpc){
    DEBUG_PRINTF("received ump bind request\n");
    errval_t err;

    struct aos_rpc_msg *msg = rpc->recv_msg;
    struct capref frame_cap = msg->cap;

    //struct capref cframe = msg->cap;
    err = lmp_chan_alloc_recv_slot(&rpc->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        abort();
    }

    coreid_t destination_core = *((coreid_t *)msg->payload);

    if(disp_get_core_id() == destination_core){
        // bind to self
        err = process_ump_bind_request(frame_cap);
        assert(err_is_ok(err));
        
    }else{
        // send UMP request to destination core
        struct capability c;
        err = cap_direct_identify(frame_cap, &c);
        assert(err_is_ok(err));

        size_t base = c.u.frame.base;
        size_t bytes = c.u.frame.bytes;
        size_t payload[2] = {base, bytes};
        err = ump_send(&ump_client_chans[destination_core], UmpBind, (char *)payload, sizeof(payload));
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "Could not send UMP message during bind request \n");
            return err_push(LIB_ERR_UMP_CHAN_BIND, err);
        }

        ump_msg_type type;
        char *recv_payload;
        size_t retsize;
        ump_receive(&ump_client_chans[destination_core], &type, &recv_payload, &retsize);
        debug_printf("done\n");
        assert(type == UmpBindReponse);
    }

    struct aos_rpc_msg *reply;
    char buf[AOS_RPC_MSG_SIZE(0)];
    err = aos_rpc_create_msg_no_pagefault(&reply, AosRpcUmpBindResponse, 0, NULL,
                                          NULL_CAP, (struct aos_rpc_msg *)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }
    // send response
    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error sending ump cap response\n");
    }
    return SYS_ERR_OK;
}

static errval_t aos_process_get_all_pids_request(struct aos_rpc *rpc)
{
    // grading
    grading_rpc_handler_process_get_all_pids();

    errval_t err = SYS_ERR_OK;
    size_t nr_of_pids;
    domainid_t *pids;
    err = process_get_all_pids(&nr_of_pids, &pids);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not get all the PIDs");
        return err;
    }

    // get remote pids
    size_t remote_nr_of_pids;
    domainid_t *remote_pids;
    err = aos_get_remote_pids(&remote_nr_of_pids, &remote_pids);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not get the remote PIDs\n");
        return err;
    }

    size_t payload_size = sizeof(size_t) + nr_of_pids * sizeof(domainid_t)
                          + remote_nr_of_pids * sizeof(domainid_t);
    void *payload = malloc(payload_size);
    if (!payload) {
        free(pids);
        return LIB_ERR_MALLOC_FAIL;
    }

    *(size_t *)payload = nr_of_pids + remote_nr_of_pids;

    memcpy(payload + sizeof(size_t), pids, nr_of_pids * sizeof(domainid_t));
    memcpy(payload + sizeof(size_t) + nr_of_pids * sizeof(domainid_t), remote_pids,
           remote_nr_of_pids * sizeof(domainid_t));

    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, AosRpcGetAllPidsResponse, payload_size, (void *)payload,
                             NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        goto unwind;
    }

    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error sending  response\n");
        goto unwind;
    }

unwind:
    free(payload);
    free(pids);

    return err;
}


errval_t init_process_msg(struct aos_rpc *rpc)
{
    // refill slot allocator
    struct slot_alloc_state *s = get_slot_alloc_state();
    if (single_slot_alloc_freecount(&s->rootca) <= 10) {
        root_slot_allocator_refill(NULL, NULL);
    }

    // should only handle incoming messages not initiated by us
    enum aos_rpc_msg_type msg_type = rpc->recv_msg->message_type;
    switch (msg_type) {
    case AosRpcSendNumber:
        aos_process_number(rpc->recv_msg);
        break;
    case AosRpcSendString:
        aos_process_string(rpc->recv_msg);
        break;
    case AosRpcRamCapRequest:
        aos_process_ram_cap_request(rpc);
        break;
    case AosRpcSpawnRequest:
        aos_process_spawn_request(rpc);
        break;
    case AosRpcSerialWriteChar:
        aos_process_serial_write_char(rpc);
        break;
    case AosRpcSerialReadChar:
        aos_process_serial_read_char_request(rpc);
        break;
    case AosRpcPid2Name:
        aos_process_pid2name_request(rpc);
        break;
    case AosRpcGetAllPids:
        aos_process_get_all_pids_request(rpc);
        break;
    case AosRpcUmpBindRequest:
        aos_process_ump_bind_request(rpc);
        break;
    default:
        printf("received unknown message type\n");
        break;
    }
    // DEBUG_PRINTF("init handled message of type: %d\n", msg_type);
    //  TODO: free msg
    return SYS_ERR_OK;
}