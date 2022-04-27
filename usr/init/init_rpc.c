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



void aos_process_number(struct aos_rpc_msg *msg)
{
    DEBUG_PRINTF("received number: %d\n", *((uint64_t *)msg->payload));
}

void aos_process_string(struct aos_rpc_msg *msg)
{
    DEBUG_PRINTF("received string: %s\n", msg->payload);
}

void aos_process_ram_cap_request(struct aos_rpc *rpc)
{
    errval_t err;

    // read ram request properties
    size_t bytes = ((size_t *)rpc->recv_msg->payload)[0];
    size_t alignment = ((size_t *)rpc->recv_msg->payload)[1];
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
    err = aos_rpc_create_msg_no_pagefault(&reply, RamCapResponse, payload_size, NULL,
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

    domainid_t pid = 0;

    if(destination_core != disp_get_core_id()){
        // send UMP request to destination core; spawn process there
        DEBUG_PRINTF("destination_core: %d\n", destination_core);
        err = ump_send(&ump_chans[destination_core], UmpSpawn, "hello", strlen("hello"));
        assert(err_is_ok(err));

        // get response!
        enum ump_msg_type type;
        char *payload;
        size_t len;
        err = ump_receive(&ump_chans[1], &type, &payload, &len);
        assert(err_is_ok(err));
        assert(type == UmpSpawnResponse);

        pid = *(domainid_t *)payload;
        DEBUG_PRINTF("launched process; PID is: %d\n", *(size_t *)payload);

    }else{
        // spawn request on this core
        struct spawninfo *info = malloc(sizeof(struct spawninfo));

        err = start_process(module, info, &pid);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to start spawn process");
            return;
        }
        DEBUG_PRINTF("spawned process with PID %d\n", pid);
    }

    size_t payload_size = sizeof(domainid_t);
    void *payload = malloc(payload_size);
    *((domainid_t *)payload) = pid;

    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, SpawnResponse, payload_size, (void *)payload,
                            NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return;
    }

    DEBUG_PRINTF("sending back!\n");
    err = aos_rpc_send_msg(rpc, reply);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error sending spawn response\n");
        return;
    }
}

errval_t aos_process_serial_write_char(struct aos_rpc *rpc)
{
    char *buf = rpc->recv_msg->payload;
    errval_t err = sys_print(buf, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error writing to serial");
        return err;
    }

    size_t payload_size = 0;
    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, SerialWriteCharResponse, payload_size, NULL,
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
    errval_t err;

    char c;
    err = sys_getchar(&c);
    if (err_is_fail(err)) {
        return err;
    }

    size_t payload_size = sizeof(char);
    void *payload = malloc(payload_size);
    *((char *)payload) = c;

    struct aos_rpc_msg *reply;
    err = aos_rpc_create_msg(&reply, SerialReadCharResponse, payload_size, payload,
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
    case SendNumber:
        aos_process_number(rpc->recv_msg);
        break;
    case SendString:
        aos_process_string(rpc->recv_msg);
        break;
    case RamCapRequest:
        aos_process_ram_cap_request(rpc);
        break;
    case SpawnRequest:
        aos_process_spawn_request(rpc);
        break;
    case SerialWriteChar:
        aos_process_serial_write_char(rpc);
        break;
    case SerialReadChar:
        aos_process_serial_read_char_request(rpc);
        break;
    default:
        printf("received unknown message type\n");
        break;
    }
    // DEBUG_PRINTF("init handled message of type: %d\n", msg_type);
    //  TODO: free msg
    return SYS_ERR_OK;
}

