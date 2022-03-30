/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>

void aos_on_receive(void *arg)
{
    errval_t err;
    DEBUG_PRINTF("receiving messsage\n");

    // receive message
    struct aos_rpc *rpc = arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref msg_cap = NULL_CAP;
    err = lmp_chan_recv(&rpc->chan, &msg, &msg_cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        DEBUG_PRINTF("message transient error\n");
        goto reregister;
    } else if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive message");
        goto reregister;
    }
    DEBUG_PRINTF("message received\n");

    // receive slot was used, allocate a new one
    if (!capref_is_null(msg_cap)) {
        err = lmp_chan_alloc_recv_slot(&rpc->chan);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to allocate receive slot");
            goto reregister;
        }
    }

reregister:
    // register again for futher messages
    err = lmp_chan_register_recv(&rpc->chan, get_default_waitset(),
                                 MKCLOSURE(aos_on_receive, rpc));
    DEBUG_ERR(err, "failed to register receive callback function");

    return;
}

/**
 * Abstraction to send a formatted message in multiple chunks.
 * @param rpc
 * @param msg
 * @return
 */
static errval_t aos_rpc_send_msg(struct aos_rpc *rpc, struct aos_rpc_msg *msg)
{
    errval_t err;
    size_t total_size = msg->header_bytes + msg->payload_bytes;

    uint64_t *buf = (uint64_t *)msg;

    size_t transferred_size;
    for (transferred_size = 0; transferred_size < total_size;
         transferred_size += 4 * sizeof(uint64_t)) {
        struct capref send_cap;
        if (transferred_size == 0 && !capcmp(msg->cap, NULL_CAP)) {
            send_cap = msg->cap;
        } else {
            send_cap = NULL_CAP;
        }

        do {
            err = lmp_chan_send(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, 4, buf[0],
                                buf[1], buf[2], buf[3]);
        } while (lmp_err_is_transient(err));

        if (err_is_fail(err)) {
            DEBUG_PRINTF("chan_send in loop\n");
            return err_push(err, LIB_ERR_LMP_CHAN_SEND);
        }
    }

    size_t remaining = total_size - transferred_size;
    switch (remaining / sizeof(uint64_t)) {
    case 1:
        err = lmp_chan_send1(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, buf[0]);
        break;
    case 2:
        err = lmp_chan_send2(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, buf[0], buf[1]);
        break;
    case 3:
        err = lmp_chan_send3(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, buf[0], buf[1],
                             buf[2]);
        break;
    default:
        if (remaining == 0) {
            err = SYS_ERR_OK;
        } else {
            err = LIB_ERR_SHOULD_NOT_GET_HERE;
        }
        break;
    }
    if (err_is_fail(err)) {
        DEBUG_PRINTF("chan_send in remaining buffer fields\n");
        return err_push(err, LIB_ERR_LMP_CHAN_SEND);
    }

    return SYS_ERR_OK;
}

/**
 * Abstraction to receive a message from possibly multiple chunks and assemble them
 * @param rpc
 * @param msg Unallocated pointer for a message struct. Will be allocaetd by this function
 * based on the size of the payload/header
 * @return
 */
static errval_t aos_rpc_recv_msg(struct aos_rpc *rpc, struct aos_rpc_msg **ret_msg)
{
    // recieve first message
    struct capref ret_cap;
    struct lmp_recv_msg recv_buffer;
    recv_buffer.buf.buflen = 4;  // unknown how large the first message is, therefore
                                 // always accept all the arguments for the first message

    errval_t err = lmp_chan_recv(&rpc->chan, &recv_buffer, &ret_cap); 

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not recieve message \n");
        return err;
    }
    // extract total size of this message from initial message
    struct aos_rpc_msg *tmp_msg = (struct aos_rpc_msg *)recv_buffer.words;
    size_t total_size = tmp_msg->header_bytes + tmp_msg->payload_bytes;  // size in bytes
    size_t full_lmp_msg_size
        = sizeof(uintptr_t)
          * 4;  // total size of an lmp message which uses all 4 arguments
    size_t recv_size = full_lmp_msg_size;  // first message contained up to 4 arguments

    // allocate space for return message, copy current message already to it
    ret_msg = malloc(total_size);  // todo: check if malloc worked
    memcpy(ret_msg, tmp_msg, MIN(recv_size, total_size));
    free(tmp_msg);

    while (recv_size <= total_size) {
        size_t remaining_size = recv_size <= total_size;
        err = lmp_chan_recv(&rpc->chan, &recv_buffer, &ret_cap);

        if(lmp_err_is_transient(err)) {
            continue;
        }

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "recieve message has an error. Ignore it and continue \n");
            return err;
        }

        size_t copy_size = MIN(remaining_size, full_lmp_msg_size);
        memcpy(ret_msg + recv_size, recv_buffer.words, copy_size);
        recv_size += copy_size;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    printf("Inside RPC_SEND_NUMBER \n");

    struct aos_rpc_msg *msg = malloc(sizeof(struct aos_rpc_msg) + sizeof(num));

    if(!msg) {
        printf("malloc failed in aos_rpc_send_number \n");
        return LIB_ERR_MALLOC_FAIL;
    }

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = sizeof(num);
    msg->cap = NULL_CAP;
    msg->message_type = SendNumber;
    msg->payload[0] = num;

    errval_t err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send number \n");
        free(msg);
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    free(msg);

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_number(struct aos_rpc *rpc, uintptr_t *ret)
{
    errval_t err;

    struct aos_rpc_msg *msg = NULL;
    err = aos_rpc_recv_msg(rpc, &msg);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not get number with RPC call \n");
        return err_push(err, LIB_ERR_RPC_RECV);
    }

    if (!msg) {
        DEBUG_PRINTF("Something went wrong \n");  // ToDo: improve error
        return LIB_ERR_SHOULD_NOT_GET_HERE;
    }

    assert(msg->message_type == SendNumber);

    *ret = (uintptr_t)*msg->payload;

    free(msg);
    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    // TODO: implement functionality to send a string over the given channel
    // and wait for a response.

    printf("Inside sending string \n");
    errval_t err;

    struct aos_rpc_msg *msg = malloc(sizeof(struct aos_rpc_msg) + strlen(string));

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = strlen(string);
    msg->message_type = SendString;
    msg->cap = NULL_CAP;
    strncpy(msg->payload, string, strlen(string));

    err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send string\n");
        free(msg);
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    free(msg);

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_string(struct aos_rpc *rpc, char *ret_string)
{
    // call rpc_get_msg(), read payload size, malloc ret_string to this size, copy string
    // to ret_string, all done :)

    struct aos_rpc_msg *msg = NULL;
    errval_t err = aos_rpc_recv_msg(rpc, &msg);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to recieve message! \n");
        free(msg);
        return err_push(err, LIB_ERR_RPC_RECV);
    }

    if (!msg) {
        DEBUG_PRINTF("Something went wrong \n");  // ToDo: improve error
        return LIB_ERR_SHOULD_NOT_GET_HERE;
    }

    assert(msg->message_type == SendString);

    ret_string = malloc(msg->payload_bytes);
    if (!ret_string) {
        printf("Failured to allocate buffer for return string in rpc get string \n");
        return LIB_ERR_MALLOC_FAIL;
    }

    strncpy(ret_string, msg->payload, msg->payload_bytes);
    free(msg);

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // TODO implement functionality to request a character from
    // the serial driver.
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.
    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    // TODO (M5): implement spawn new process rpc
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    // TODO (M5): implement name lookup for process given a process id
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    // TODO (M5): implement process id discovery
    return SYS_ERR_OK;
}


errval_t aos_rpc_init_chan_to_child(struct aos_rpc *init_rpc, struct aos_rpc *child_rpc)
{
    errval_t err;

    // setup channel of memeater
    lmp_chan_init(&child_rpc->chan);

    child_rpc->chan.endpoint = init_rpc->chan.endpoint;

    struct capref memeater_endpoint_cap;
    err = slot_alloc(&memeater_endpoint_cap);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("Failed to allocate slot for memeater endpoint\n");
    }
    assert(err_is_ok(err));

    while (1) {
        struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;

        lmp_endpoint_set_recv_slot(child_rpc->chan.endpoint, memeater_endpoint_cap);
        err = lmp_endpoint_recv(child_rpc->chan.endpoint, &recv_msg.buf,
                                &memeater_endpoint_cap);
        if (err_is_fail(err)) {
            if (err == LIB_ERR_NO_LMP_MSG || lmp_err_is_transient(err)) {
                // DEBUG_ERR(err, "no lmp msg, or is transiend: continue! \n");
                continue;
            } else {
                DEBUG_ERR(err, "loop in main, !err_is_transient \n");
                assert(0);
            }
        } else {
            // TODO caution: si is on stack & memeater_endpoint_cap is on stack
            // si.endpoint = &memeater_endpoint_cap;
            break;
        }
    }

    child_rpc->chan.local_cap = cap_initep;
    child_rpc->chan.remote_cap = memeater_endpoint_cap;

    printf("init local\n");
    char buf0[256];
    debug_print_cap_at_capref(buf0, 256, child_rpc->chan.local_cap);
    debug_printf("%.*s\n", 256, buf0);

    printf("init remote\n");
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, child_rpc->chan.remote_cap);
    debug_printf("%.*s\n", 256, buf1);

    err = lmp_chan_send0(&child_rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send acknowledgement");
    }
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

/**
 *  \brief Initialize an aos_rpc struct. Sets up channel to remote endpoint (init)
 *
 *  \param aos_rpc The aos_rpc struct to initialize.
 *
 **/
errval_t aos_rpc_init(struct aos_rpc *aos_rpc)
{
    errval_t err;

    // TODO MILESTONE 3: register ourselves with init
    /* allocate lmp channel structure */

    /* create local endpoint */
    lmp_chan_init(&aos_rpc->chan);

    struct lmp_endpoint *ep = malloc(sizeof(struct lmp_endpoint));
    assert(ep);

    aos_rpc->chan.endpoint = ep;
    err = endpoint_create(8, &aos_rpc->chan.local_cap, &aos_rpc->chan.endpoint);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not create endpoint in child \n");
        return err;
    }

    /* set remote endpoint to init's endpoint */
    aos_rpc->chan.remote_cap = cap_initep;
    set_init_rpc(aos_rpc);

    /* set receive handler */
    err = lmp_chan_register_recv(&aos_rpc->chan, get_default_waitset(),
                                 MKCLOSURE(aos_handshake_recv_closure, &aos_rpc->chan));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not register recv handler in child \n");
        return err;
    }

    /* send local ep to init */
    err = lmp_chan_send0(&aos_rpc->chan, LMP_SEND_FLAGS_DEFAULT, aos_rpc->chan.local_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send child endpoint cap to init\n");
        return err;
    }

    /* wait for init to acknowledge receiving the endpoint */
    while (!lmp_chan_can_recv(&aos_rpc->chan)) {
        err = event_dispatch(get_default_waitset());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    };

    printf("memeater local\n");
    char buf0[256];
    debug_print_cap_at_capref(buf0, 256, aos_rpc->chan.local_cap);
    debug_printf("%.*s\n", 256, buf0);

    printf("memeater remote\n");
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, aos_rpc->chan.remote_cap);
    debug_printf("%.*s\n", 256, buf1);

    /* initialize init RPC client with lmp channel */

    /* set init RPC client in our program state */

    /* TODO MILESTONE 3: now we should have a channel with init set up and can
     * use it for the ram allocator */

    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here

    return SYS_ERR_OK;
}

void aos_handshake_recv_closure(void *arg)
{
    errval_t err;

    printf("Inside handshake recv closure\n");

    struct lmp_chan *lc = arg;
    struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
    struct capref cap;

    err = lmp_chan_recv(lc, &recv_msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        DEBUG_ERR(err, "lmp transient error received");
        lmp_chan_register_recv(lc, get_default_waitset(),
                               MKCLOSURE(aos_handshake_recv_closure, lc));
        return;
    } else if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive message");
        // TODO this needs to be handled properly for handshake!
        // e.g.: terminate child process? retry?
        return;
    }
    debug_printf("msg length: %d\n", recv_msg.buf.msglen);

    lmp_chan_register_recv(lc, get_default_waitset(),
                           MKCLOSURE(aos_handshake_recv_closure, lc));
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    // TODO: Return channel to talk to memory server process (or whoever
    // implements memory server functionality)
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    // TODO: Return channel to talk to process server process (or whoever
    // implements process server functionality)
    debug_printf("aos_rpc_get_process_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    debug_printf("aos_rpc_get_serial_channel NYI\n");
    return NULL;
}
