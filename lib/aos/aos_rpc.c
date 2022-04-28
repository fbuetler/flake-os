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
#include <math.h>
#include <spawn/spawn.h>
#include <aos/deferred.h>

#define AOS_RPC_MSG_SIZE(payload_size) (sizeof(struct aos_rpc_msg) + (payload_size))
char static_rpc_msg_buf[1<<20];

/**
 * @brief handler for handshake messages
 *
 * @param msg
 */
static void aos_process_handshake(struct aos_rpc_msg *msg)
{
    DEBUG_PRINTF("Handshake ACK\n");
}

/**
 * @brief default handler for number messages
 *
 * @param msg
 */
static void aos_process_number(struct aos_rpc_msg *msg)
{
    DEBUG_PRINTF("received number: %d\n", *((uint64_t *)msg->payload));
    free(msg);
}

/**
 * @brief default handler for string messages
 *
 * @param ms
 * g
 */
static void aos_process_string(struct aos_rpc_msg *msg)
{
    DEBUG_PRINTF("received string: %s\n", msg->payload);
    free(msg);
}

static errval_t aos_rpc_process_msg(struct aos_rpc *rpc)
{
    // should only handle incoming messages not initiated by us
    enum aos_rpc_msg_type msg_type = rpc->recv_msg->message_type;
    switch (msg_type) {
    case Handshake:
        aos_process_handshake(rpc->recv_msg);
        break;
    case SendNumber:
        aos_process_number(rpc->recv_msg);
        break;
    case SendString:
        aos_process_string(rpc->recv_msg);
        break;
    case GetAllPidsResponse:
        break;
    default:
        DEBUG_PRINTF("received unknown message type %d\n", msg_type);
        // free(rpc->recv_msg);
        break;
    }
    // TODO: free msg
    return SYS_ERR_OK;
}

// forward declared
static errval_t aos_rpc_recv_msg(struct aos_rpc *rpc);
static errval_t aos_rpc_recv_msg_blocking(struct aos_rpc *rpc);

static errval_t aos_rpc_recv_msg_handler(void *args)
{
    errval_t err;
    struct aos_rpc *rpc = (struct aos_rpc *)args;

    err = aos_rpc_recv_msg(rpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive message");
        return err;
    }

    if (!rpc->is_busy) {
        rpc->process_msg_func(rpc);
    }

    return SYS_ERR_OK;
}

__attribute__((unused))
static char STATIC_RPC_RECV_MSG_BUF[4096];
/**
 * @brief Helper function which extracts the first LMP message
 * 
 * @param rpc 
 * @param msg_cap 
 * @param recv_buf 
 * @return errval_t 
 */
static errval_t aos_rpc_recv_first_msg(struct aos_rpc *rpc, struct capref *msg_cap, struct lmp_recv_msg *recv_buf) {
    struct aos_rpc_msg *tmp_msg = (struct aos_rpc_msg *)recv_buf->words;
    size_t total_bytes = tmp_msg->header_bytes + tmp_msg->payload_bytes;

    size_t recv_bytes = MIN(LMP_MSG_LENGTH_BYTES, total_bytes);

    // allocate space for return message, copy current message already to it
    //DEBUG_PRINTF("use_dynamic_buf: %d \n", rpc->use_dynamic_buf);
    rpc->recv_msg = (!rpc->use_dynamic_buf) ? (struct aos_rpc_msg *)rpc->buf: malloc(total_bytes);
    if (!rpc->recv_msg) {
        DEBUG_PRINTF("Malloc inside aos_rpc_recv_msg_handler for ret_msg failed "
                        "\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(rpc->recv_msg, tmp_msg, recv_bytes);
    rpc->recv_bytes = recv_bytes;
    rpc->is_busy = true;
    rpc->recv_msg->cap = *msg_cap;

    return SYS_ERR_OK;
    
}

/**
 * @brief Helper function which extracts a followup LMP message
 * 
 * @param rpc 
 * @param recv_buf 
 * @return errval_t 
 */
static errval_t aos_rpc_recv_followup_msg(struct aos_rpc *rpc,  struct lmp_recv_msg *recv_buf) {
    size_t total_bytes = rpc->recv_msg->header_bytes + rpc->recv_msg->payload_bytes;
    size_t remaining_bytes = total_bytes - rpc->recv_bytes;
    size_t copy_bytes = MIN(remaining_bytes, LMP_MSG_LENGTH_BYTES);
    memcpy(((char *)rpc->recv_msg) + rpc->recv_bytes, recv_buf->words, copy_bytes);
    rpc->recv_bytes += copy_bytes;

    return SYS_ERR_OK;
}

/**
 * @brief Helper function to block until the channel has a new message
 * 
 * @param rpc 
 * @param msg_cap 
 * @param recv_buf 
 * @return errval_t 
 */
static errval_t aos_rpc_chan_recv_blocking(struct aos_rpc *rpc, struct capref * msg_cap, struct lmp_recv_msg *recv_buf ) {
    errval_t err;
    while (!lmp_chan_can_recv(&rpc->chan)) {}
    while (true)
    {
        err = lmp_chan_recv(&rpc->chan, recv_buf, msg_cap); 
        if(err_is_fail(err) && lmp_err_is_transient(err)) {
            continue;
        } else if (err_is_fail(err)){
            return err_push(err, LIB_ERR_LMP_CHAN_RECV);
        } else {
            break;
        }
    }
    return SYS_ERR_OK;
}

/**
 * @brief Block until all the individual messages were recieved
 * 
 * @param rpc 
 * @return errval_t 
 */
__attribute__((unused))
static errval_t aos_rpc_recv_msg_blocking(struct aos_rpc *rpc)
{
    errval_t err;
    // receive first message
    struct capref msg_cap;
    struct lmp_recv_msg recv_buf = LMP_RECV_MSG_INIT;

    err = aos_rpc_chan_recv_blocking(rpc, &msg_cap, &recv_buf);


    if (!rpc->is_busy) { 
        err = aos_rpc_recv_first_msg(rpc, &msg_cap, &recv_buf);
    } 

    while(rpc->recv_bytes < rpc->recv_msg->payload_bytes + rpc->recv_msg->header_bytes) {
        err = aos_rpc_chan_recv_blocking(rpc, &msg_cap, &recv_buf);
        err = aos_rpc_recv_followup_msg(rpc, &recv_buf);
    }
    
    rpc->is_busy = false;
    return err;
}

/**
 * @brief Async recieve
 * 
 * @param rpc 
 * @return errval_t 
 */
static errval_t aos_rpc_recv_msg(struct aos_rpc *rpc)
{
    errval_t err;
    // receive first message
    struct capref msg_cap;
    struct lmp_recv_msg recv_buf = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(&rpc->chan, &recv_buf, &msg_cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        goto reregister;
    } else if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_RECV);
    }


    if (!rpc->is_busy) {
        aos_rpc_recv_first_msg(rpc, &msg_cap, &recv_buf);
        /*
        // setup rpc state with new message and set to busy
        struct aos_rpc_msg *tmp_msg = (struct aos_rpc_msg *)recv_buf.words;
        size_t total_bytes = tmp_msg->header_bytes + tmp_msg->payload_bytes;

        size_t recv_bytes = MIN(LMP_MSG_LENGTH_BYTES, total_bytes);

        // DEBUG_PRINTF("Received bytes: %zu total_bytes: %zu", recv_bytes, total_bytes);

        // allocate space for return message, copy current message already to it
        rpc->recv_msg = (!rpc->use_dynamic_buf) ? (struct aos_rpc_msg *)STATIC_RPC_RECV_MSG_BUF : malloc(total_bytes);
        if (!rpc->recv_msg) {
            DEBUG_PRINTF("Malloc inside aos_rpc_recv_msg_handler for ret_msg failed "
                         "\n");
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(rpc->recv_msg, tmp_msg, recv_bytes);
        rpc->recv_bytes = recv_bytes;
        rpc->is_busy = true;
        rpc->recv_msg->cap = msg_cap;
        */
    } else {
        aos_rpc_recv_followup_msg(rpc, &recv_buf);
        /*
        size_t total_bytes = rpc->recv_msg->header_bytes + rpc->recv_msg->payload_bytes;
        size_t remaining_bytes = total_bytes - rpc->recv_bytes;
        // DEBUG_PRINTF("Recv: total bytes: %zu msg_header: %hu msg_payload %d ,
        // recv_bytes: %zu \n", total_bytes,  rpc->recv_msg->header_bytes,
        // rpc->recv_msg->payload_bytes, rpc->recv_bytes);

        size_t copy_bytes = MIN(remaining_bytes, LMP_MSG_LENGTH_BYTES);
        // DEBUG_PRINTF("Copy bytes: %zu \n", copy_bytes);
        // DEBUG_PRINTF("buffer content: %s \n", (char*)recv_buf.words);
        memcpy(((char *)rpc->recv_msg) + rpc->recv_bytes, recv_buf.words, copy_bytes);
        rpc->recv_bytes += copy_bytes;
        */
    }

    if (rpc->recv_bytes < rpc->recv_msg->payload_bytes + rpc->recv_msg->header_bytes) {
        goto reregister;
    }

    if (!capref_is_null(msg_cap)) {
        // TODO chan_alloc_recv needs to be inserted somewhere now!
    }

    rpc->is_busy = false;

reregister:
    lmp_chan_register_recv(&rpc->chan, get_default_waitset(),
                           MKCLOSURE((void (*)(void *))aos_rpc_recv_msg_handler, rpc));
    return SYS_ERR_OK;
}

errval_t aos_rpc_init_chan_to_child(struct aos_rpc *init_rpc, struct aos_rpc *child_rpc)
{
    errval_t err;

    struct capref init_ep_cap = child_rpc->chan.local_cap;

    // will contain endpoint cap of child
    struct capref memeater_endpoint_cap;
    err = slot_alloc(&memeater_endpoint_cap);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("Failed to allocate slot for memeater endpoint\n");
        return err;
    }

    while (1) {
        struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;

        lmp_endpoint_set_recv_slot(child_rpc->chan.endpoint, memeater_endpoint_cap);
        err = lmp_endpoint_recv(child_rpc->chan.endpoint, &recv_msg.buf,
                                &memeater_endpoint_cap);
        if (err_is_fail(err)) {
            if (err == LIB_ERR_NO_LMP_MSG || lmp_err_is_transient(err)) {
                continue;
            } else {
                DEBUG_ERR(err, "loop in main, !err_is_transient \n");
                return err;
            }
        } else {
            break;
        }
    }
    // we've received the capability;

    child_rpc->chan.local_cap = init_ep_cap;
    child_rpc->chan.remote_cap = memeater_endpoint_cap;
    init_rpc->chan.remote_cap = memeater_endpoint_cap;

    // char buf0[256];
    // debug_print_cap_at_capref(buf0, 256, child_rpc->chan.local_cap);
    // DEBUG_PRINTF("local: %.*s\n", 256, buf0);
    // char buf1[256];
    // debug_print_cap_at_capref(buf1, 256, child_rpc->chan.remote_cap);
    // DEBUG_PRINTF("remote %.*s\n", 256, buf1);

    size_t payload_size = 0;
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, Handshake, payload_size, NULL,
                             child_rpc->chan.local_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_send_msg(child_rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send acknowledgement");
    }

    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

static struct lmp_endpoint static_ep;
/**
 *  \brief Initialize an aos_rpc struct. Sets up channel to remote endpoint (init)
 *
 *  \param aos_rpc The aos_rpc struct to initialize.
 *
 **/

errval_t aos_rpc_init(struct aos_rpc *aos_rpc)
{
    errval_t err;

    thread_mutex_init(&ram_mutex);

    aos_rpc->buf = STATIC_RPC_RECV_MSG_BUF;

    // initial state
    aos_rpc->is_busy = false;

    // MILESTONE 3: register ourselves with init
    /* allocate lmp channel structure */

    /* create local endpoint */
    lmp_chan_init(&aos_rpc->chan);

    // struct lmp_endpoint *ep = malloc(sizeof(struct lmp_endpoint));
    // assert(ep);
    struct lmp_endpoint *ep = &static_ep;
    aos_rpc->chan.endpoint = ep;
    err = endpoint_create(256, &aos_rpc->chan.local_cap, &aos_rpc->chan.endpoint);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not create endpoint in child \n");
        return err;
    }
    aos_rpc->chan.buflen_words = 256;

    /* set remote endpoint to init's endpoint */
    aos_rpc->chan.remote_cap = cap_initep;
    set_init_rpc(aos_rpc);

    /* send local ep to init */
    err = lmp_chan_send0(&aos_rpc->chan, LMP_SEND_FLAGS_DEFAULT, aos_rpc->chan.local_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send child endpoint cap to init\n");
        return err;
    }

    err = aos_rpc_register_recv(aos_rpc, aos_rpc_process_msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not register recv handler in child \n");
        return err;
    }


    get_default_waitset();

    err = event_dispatch(get_default_waitset());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in event dispatch\n");
        abort();
    }

    /* initialize init RPC client with lmp channel */

    /* set init RPC client in our program state */

    /* TODO MILESTONE 3: now we should have a channel with init set up and can
     * use it for the ram allocator */

    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here

    return SYS_ERR_OK;
}


errval_t aos_rpc_create_msg_no_pagefault(struct aos_rpc_msg **ret_msg, enum aos_rpc_msg_type msg_type,
                            size_t payload_size, void *payload, struct capref msg_cap, struct aos_rpc_msg *msg)
{
    size_t header_size = sizeof(struct aos_rpc_msg);

    msg->message_type = msg_type;
    msg->header_bytes = header_size;
    msg->payload_bytes = payload_size;
    msg->cap = msg_cap;

    memcpy(msg->payload, payload, payload_size);


    if (ret_msg) {
        *ret_msg = msg;
    }

    return SYS_ERR_OK;
}



/**
 * @brief helper to create a message that should be sent
 *
 * @param ret_msg
 * @param msg_type
 * @param payload_size
 * @param payload
 * @param msg_cap
 * @return errval_t
 */
errval_t aos_rpc_create_msg(struct aos_rpc_msg **ret_msg, enum aos_rpc_msg_type msg_type,
                            size_t payload_size, void *payload, struct capref msg_cap)
{
    size_t header_size = sizeof(struct aos_rpc_msg);
    struct aos_rpc_msg *msg = malloc(
        ROUND_UP(header_size + payload_size, sizeof(uintptr_t)));
    if (!msg) {
        DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "failed to allocate memory");
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->message_type = msg_type;
    msg->header_bytes = header_size;
    msg->payload_bytes = payload_size;
    msg->cap = msg_cap;
    memcpy(msg->payload, payload, payload_size);

    if (ret_msg) {
        *ret_msg = msg;
    }

    return SYS_ERR_OK;
}

/**
 * @brief Abstraction to send a formatted message in multiple chunks.
 *
 * @param rpc
 * @param msg
 *
 * @return
 */
errval_t aos_rpc_send_msg(struct aos_rpc *rpc, struct aos_rpc_msg *msg)
{
    errval_t err;

    size_t total_bytes = msg->header_bytes + msg->payload_bytes;

    uint64_t *buf = (uint64_t *)msg;

    struct capref send_cap;
    if (!capcmp(msg->cap, NULL_CAP)) {
        send_cap = msg->cap;
    } else {
        send_cap = NULL_CAP;
    }

    size_t transferred_size = 0;

    while (transferred_size < total_bytes
           && ceil((double)(total_bytes - transferred_size) / (double)sizeof(uint64_t))
                  >= 4) {
        do {
            err = lmp_chan_send(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, 4, buf[0],
                                buf[1], buf[2], buf[3]);
        } while (lmp_err_is_transient(err));
        if (err_is_fail(err)) {
            DEBUG_PRINTF("chan_send in loop\n");
            return err_push(err, LIB_ERR_LMP_CHAN_SEND);
        }

        buf += 4;
        transferred_size += 4 * sizeof(uint64_t);
    }


    size_t remaining;
    if (transferred_size >= total_bytes)
        remaining = 0;
    else
        remaining = total_bytes - transferred_size;

    do {
        switch (DIVIDE_ROUND_UP(remaining, sizeof(uint64_t))) {
        case 0:
            if (remaining == 0) {
                err = SYS_ERR_OK;
                break;
            }
            // continue in case 1 for leftover stuff?
        case 1:
            err = lmp_chan_send1(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, buf[0]);
            break;
        case 2:
            err = lmp_chan_send2(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, buf[0],
                                 buf[1]);
            break;
        case 3:
            err = lmp_chan_send3(&rpc->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, buf[0],
                                 buf[1], buf[2]);
            break;
        default:
            if (remaining == 0) {
                err = SYS_ERR_OK;
            } else {
                DEBUG_PRINTF("inside msg_send. Should not get here \n");
                err = LIB_ERR_SHOULD_NOT_GET_HERE;
            }
            break;
        }
    } while (lmp_err_is_transient(err));
    if (err_is_fail(err)) {
        DEBUG_PRINTF("chan_send in remaining buffer fields\n");
        return err_push(err, LIB_ERR_LMP_CHAN_SEND);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_register_recv(struct aos_rpc *rpc, process_msg_func_t process_msg_func)
{
    errval_t err;

    rpc->process_msg_func = process_msg_func;

    err = lmp_chan_alloc_recv_slot(&rpc->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    err = lmp_chan_register_recv(
        &rpc->chan, get_default_waitset(),
        MKCLOSURE((void (*)(void *))aos_rpc_recv_msg_handler, rpc));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to register receive function");
        return err_push(err, LIB_ERR_LMP_CHAN_INIT);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_call(struct aos_rpc *rpc, struct aos_rpc_msg *msg, bool use_dynamic_buf)
{
    thread_mutex_lock_nested(&get_current_paging_state()->paging_mutex);
    errval_t err;

    // send message
    //DEBUG_PRINTF("inside aos_rpc_call, before aos_rpc_send_msg \n");
    //DEBUG_PRINTF("channel %p\n", rpc->chan.endpoint);
    rpc->use_dynamic_buf = use_dynamic_buf;

    err = aos_rpc_send_msg(rpc, msg);
    //DEBUG_PRINTF("inside aos_rpc_call, after aos_rpc_send_msg \n");
    //DEBUG_PRINTF("channel after %p\n", rpc->chan.endpoint);
    //DEBUG_PRINTF("recv_bytes: %d, is_busy: %d \n", rpc->recv_bytes, rpc->is_busy);
    
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    /*
    while (!lmp_chan_can_recv(&rpc->chan)) {
    }
    */

    //err = aos_rpc_recv_msg(rpc);
    
    err = aos_rpc_recv_msg_blocking(rpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive message");
        // TODO remove abort
        abort();
        return err;
    }

    /*
    while(rpc->is_busy){
        // wait for the response message
        while (!lmp_chan_can_recv(&rpc->chan)) {
        }   
        event_dispatch(get_default_waitset());
    }
    */

    thread_mutex_unlock(&get_current_paging_state()->paging_mutex);

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err;
    struct aos_rpc_msg *msg;

    char msg_buf[AOS_RPC_MSG_SIZE(sizeof(uintptr_t))];
    err = aos_rpc_create_msg_no_pagefault(&msg, SendNumber, sizeof(num), (void *)&num, NULL_CAP, (struct aos_rpc_msg *)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err;

    size_t payload_size = strlen(string);
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, SendString, payload_size, (void *)string, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send string\n");
        free(msg);
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    free(msg);

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    errval_t err = lmp_chan_alloc_recv_slot(&rpc->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        abort();
    }  

    size_t payload_size = 2 * sizeof(size_t);
    char payload[payload_size];
    ((size_t *)payload)[0] = bytes;
    ((size_t *)payload)[1] = alignment;

    struct aos_rpc_msg *msg;

    char buf[AOS_RPC_MSG_SIZE(payload_size)];
    err = aos_rpc_create_msg_no_pagefault(&msg, RamCapRequest, payload_size, (void *)payload, NULL_CAP, (struct aos_rpc_msg*)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_call(rpc, msg, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    if(rpc->recv_msg->message_type != RamCapResponse){
        DEBUG_PRINTF("message type is not RamCapResponse, it's %d\n", rpc->recv_msg->message_type);
    }

    *ret_cap = (struct capref)rpc->recv_msg->cap;

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // TODO implement functionality to request a character from
    // the serial driver.

    errval_t err;

    size_t payload_size = 0;

    char msg_buf[AOS_RPC_MSG_SIZE(payload_size)];

    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg_no_pagefault(&msg, SerialReadChar, payload_size, NULL, NULL_CAP, (struct aos_rpc_msg*)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_call(rpc, msg, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    char c = ((char *)rpc->recv_msg->payload)[0];
    *retc = c;

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.

    errval_t err = SYS_ERR_OK;

    size_t payload_size = sizeof(char);
    void *payload = malloc(payload_size);
    ((char *)payload)[0] = c;

    char msg_buf[AOS_RPC_MSG_SIZE(payload_size)];

    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg_no_pagefault(&msg, SerialWriteChar, payload_size, (void *)payload,
                             NULL_CAP, (struct aos_rpc_msg*)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_call(rpc, msg, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    return err;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    // TODO (M5): implement spawn new process rpc
    errval_t err;

    size_t cmdline_len = strlen(cmdline);
    size_t payload_size = sizeof(coreid_t) + cmdline_len + 1;
    struct aos_rpc_msg *msg;
    char *payload = (char *)malloc(payload_size);
    if(!payload){
        return LIB_ERR_MALLOC_FAIL;
    }

    *(coreid_t*)payload = core;
    memcpy(payload + sizeof(coreid_t), cmdline, cmdline_len +1);
    err = aos_rpc_create_msg(&msg, SpawnRequest, payload_size, (void *)payload, NULL_CAP);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    DEBUG_PRINTF("spawning...\n");

    err = aos_rpc_call(rpc, msg, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        free(payload);
        return err;
    }

    domainid_t assigned_pid = *((domainid_t *)rpc->recv_msg->payload);
    DEBUG_PRINTF("spawned process with PID 0x%lx\n", assigned_pid);
    *newpid = assigned_pid;
    free(msg);
    free(payload);

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    // TODO (M5): implement name lookup for process given a process id
    errval_t err;
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, Pid2Name, sizeof(domainid_t), (void *)&pid, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_call(rpc, msg, true); // rpc->recv_msg is malloced. Need to free it
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    char *assigned_name = rpc->recv_msg->payload;
    struct aos_rpc_msg * tmp_ptr = rpc->recv_msg;

    if(*assigned_name == 0){
        DEBUG_PRINTF("no pid assigned to this!\n");
    }

    size_t name_len = strlen(assigned_name);
    *name = (char *) malloc(name_len+1);
    if(!*name){
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(*name, assigned_name, name_len + 1);
    free(msg);
    free(tmp_ptr);

    return SYS_ERR_OK;
}

/**
 * 
 * @brief RPC call to get all process pids. pids is malloced and needs to be freed by caller 
 * 
 * @param rpc 
 * @param pids 
 * @param pid_count 
 * @return errval_t 
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    DEBUG_PRINTF("get all pids!\n");
    // TODO (M5): implement process id discovery
    errval_t err;

    size_t payload_size = 0;

    char msg_buf[AOS_RPC_MSG_SIZE(payload_size)];

    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg_no_pagefault(&msg, GetAllPids, payload_size, NULL, NULL_CAP, (struct aos_rpc_msg*)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_call(rpc, msg, false);  // rpc->recv_msg is malloced. Need to free it

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    *pid_count = *((size_t *)rpc->recv_msg->payload);
    //*pids = ((domainid_t *)(rpc->recv_msg->payload + sizeof(size_t)));

    *pids = malloc(*pid_count*sizeof(domainid_t));
    memcpy(*pids, rpc->recv_msg->payload + sizeof(size_t), *pid_count*sizeof(domainid_t));

    //free(rpc->recv_msg);

    return SYS_ERR_OK;
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
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    return get_init_rpc();
}
