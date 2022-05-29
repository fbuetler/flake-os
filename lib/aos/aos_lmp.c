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

#include <grading.h>
#include <aos/aos.h>
#include <aos/aos_lmp.h>
#include <aos/aos_rpc.h>
#include <math.h>
#include <spawn/spawn.h>
#include <aos/deferred.h>

char static_rpc_msg_buf[1 << 20];

/**
 * @brief handler for handshake messages
 *
 * @param msg
 */
static void aos_process_handshake(struct aos_lmp_msg *msg)
{
    DEBUG_PRINTF("Handshake ACK\n");
}

/**
 * @brief default handler for number messages
 *
 * @param msg
 */
void aos_process_number(struct aos_lmp *lmp)
{
    errval_t err;

    uintptr_t number = *((uint64_t *)lmp->recv_msg->payload);
    grading_rpc_handle_number(number);
    DEBUG_PRINTF("received number: %d\n", number);

    // create response with ram cap
    size_t payload_size = 0;
    struct aos_lmp_msg *reply;
    char buf[AOS_LMP_MSG_SIZE(payload_size)];
    err = aos_lmp_create_msg_no_pagefault(&reply, AosRpcSendNumberResponse, payload_size,
                                          NULL, NULL_CAP, (struct aos_lmp_msg *)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return;
    }

    err = aos_lmp_send_msg(lmp, reply);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error sending number response\n");
    }
}

/**
 * @brief default handler for string messages
 *
 * @param ms
 * g
 */
void aos_process_string(struct aos_lmp *lmp)
{
    grading_rpc_handler_string(lmp->recv_msg->payload);
    DEBUG_PRINTF("received string: %s\n", lmp->recv_msg->payload);
    // TODO still required?
    // free(msg);

    size_t payload_size = 0;
    struct aos_lmp_msg *reply;
    char buf[AOS_LMP_MSG_SIZE(payload_size)];
    errval_t err = aos_lmp_create_msg_no_pagefault(&reply, AosRpcSendStringResponse,
                                                   payload_size, NULL, NULL_CAP,
                                                   (struct aos_lmp_msg *)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create string response message");
        return;
    }

    err = aos_lmp_send_msg(lmp, reply);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error sending string response msg\n");
    }
}

static errval_t aos_rpc_process_lmp_bind(struct aos_lmp *lmp)
{
    // DEBUG_PRINTF("Received LMP bind request\n");
    errval_t err;

    struct aos_lmp_msg *msg = lmp->recv_msg;
    struct capref client_ep_cap = msg->cap;

    // DEBUG_PRINTF("Allocating new RPC\n");
    struct aos_lmp *new = malloc(sizeof(struct aos_lmp));
    if (new == NULL) {
        DEBUG_PRINTF("Failed to allocate new LMP binding\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    // DEBUG_PRINTF("Initialize LMP endpoint\n");
    err = aos_lmp_init(new, client_ep_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to initialize new LMP binding to client");
        return err_push(err, LIB_ERR_LMP_INIT);
    }

    err = aos_lmp_initiate_handshake(new);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to initiate handshake to client");
        return err_push(err, LIB_ERR_LMP_INIT_HANDSHAKE);
    }

    // DEBUG_PRINTF("Register receive handler\n");
    err = aos_lmp_register_recv(new, aos_lmp_server_event_handler);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register receive function for new LMP binding");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_lmp_server_event_handler(struct aos_lmp *lmp)
{
    aos_rpc_msg_type_t msg_type = lmp->recv_msg->message_type;
    switch (msg_type) {
    case AosRpcHandshake:
        aos_process_handshake(lmp->recv_msg);
        break;
    case AosRpcClientRequest: {
        DEBUG_PRINTF("Handling client request\n")
        struct aos_lmp_msg *msg = lmp->recv_msg;
        struct aos_rpc_msg request = { .type = msg->message_type,
                                       .payload = msg->payload,
                                       .bytes = msg->payload_bytes,
                                       .cap = msg->cap };
        struct aos_rpc_msg response;
        response.cap = NULL_CAP;
        aos_rpc_process_client_request(&request, &response);

        DEBUG_PRINTF("Done handling client request\n");
        struct aos_lmp_msg *ret_msg;
        aos_lmp_create_msg(&ret_msg, AosRpcServerResponse, response.bytes,
                           response.payload, response.cap);
        aos_lmp_send_msg(lmp, ret_msg);
        free(ret_msg);
        break;
    }
    default:
        DEBUG_PRINTF("received unknown message type %d, server only handles client "
                     "requests\n",
                     msg_type);
        break;
    }

    aos_lmp_msg_free(lmp);

    return SYS_ERR_OK;
}

errval_t aos_lmp_event_handler(struct aos_lmp *lmp)
{
    // should only handle incoming messages not initiated by us
    struct aos_lmp_msg *msg = lmp->recv_msg;
    aos_rpc_msg_type_t msg_type = msg->message_type;
    switch (msg_type) {
    case AosRpcHandshake:
        aos_process_handshake(lmp->recv_msg);
        break;
    case AosRpcSendNumber:
        aos_process_number(lmp);
        break;
    case AosRpcSendString:
        aos_process_string(lmp);
        break;
    case AosRpcLmpBind:
        aos_rpc_process_lmp_bind(lmp);
        break;
    case AosRpcGetAllPidsResponse:
        break;
    default:
        DEBUG_PRINTF("received unknown message type %d\n", msg_type);
        break;
    }

    aos_lmp_msg_free(lmp);

    return SYS_ERR_OK;
}

// forward declared
static errval_t aos_lmp_recv_msg(struct aos_lmp *lmp);
static errval_t aos_lmp_recv_msg_blocking(struct aos_lmp *lmp);

static errval_t aos_lmp_recv_msg_handler(void *args)
{
    errval_t err;
    struct aos_lmp *lmp = (struct aos_lmp *)args;

    err = aos_lmp_recv_msg(lmp);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive message");
        return err;
    }

    if (!lmp->is_busy) {
        lmp->process_msg_func(lmp);
    }

    return SYS_ERR_OK;
}

/**
 * @brief Helper function to free an LMP message contained in a struct aos_lmp
 *        This function will set lmp->recv_bytes to 0, in case it uses a
 *        dynamic buffer, free the lmp->recv_msg, and set the lmp->recv_msg to NULL.
 *
 * @param lmp pointer to the LMP channel instance
 */
void aos_lmp_msg_free(struct aos_lmp *lmp)
{
    lmp->recv_bytes = 0;

    if (lmp->use_dynamic_buf) {
        free(lmp->recv_msg);
    }

    lmp->recv_msg = NULL;
}

__attribute__((unused)) static char STATIC_RPC_RECV_MSG_BUF[4096];
/**
 * @brief Helper function which extracts the first LMP message
 *        If the LMP channel uses a dynamic buffer, then the message is malloced
 *        and needs to be freed. Otherwise, a static buffer is used.
 *        A message should be freed using aos_lmp_msg_free.
 *
 * @param lmp
 * @param msg_cap
 * @param recv_buf
 * @return errval_t
 */
static errval_t aos_lmp_recv_first_msg(struct aos_lmp *lmp, struct capref *msg_cap,
                                       struct lmp_recv_msg *recv_buf)
{
    struct aos_lmp_msg *tmp_msg = (struct aos_lmp_msg *)recv_buf->words;
    size_t total_bytes = tmp_msg->header_bytes + tmp_msg->payload_bytes;

    size_t recv_bytes = MIN(LMP_MSG_LENGTH_BYTES, total_bytes);

    // allocate space for return message, copy current message already to it
    // DEBUG_PRINTF("use_dynamic_buf: %d \n", lmp->use_dynamic_buf);
    lmp->recv_msg = (!lmp->use_dynamic_buf) ? (struct aos_lmp_msg *)lmp->buf
                                            : malloc(total_bytes);
    if (!lmp->recv_msg) {
        DEBUG_PRINTF("Malloc inside aos_lmp_recv_msg_handler for ret_msg failed"
                     "\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(lmp->recv_msg, tmp_msg, recv_bytes);
    lmp->recv_bytes = recv_bytes;
    lmp->is_busy = true;
    lmp->recv_msg->cap = *msg_cap;

    return SYS_ERR_OK;
}

/**
 * @brief Helper function which extracts a followup LMP message
 *
 * @param lmp
 * @param recv_buf
 * @return errval_t
 */
static errval_t aos_lmp_recv_followup_msg(struct aos_lmp *lmp,
                                          struct lmp_recv_msg *recv_buf)
{
    size_t total_bytes = lmp->recv_msg->header_bytes + lmp->recv_msg->payload_bytes;
    size_t remaining_bytes = total_bytes - lmp->recv_bytes;
    size_t copy_bytes = MIN(remaining_bytes, LMP_MSG_LENGTH_BYTES);
    memcpy(((char *)lmp->recv_msg) + lmp->recv_bytes, recv_buf->words, copy_bytes);
    lmp->recv_bytes += copy_bytes;

    return SYS_ERR_OK;
}

/**
 * @brief Helper function to block until the channel has a new message
 *
 * @param lmp
 * @param msg_cap
 * @param recv_buf
 * @return errval_t
 */
static errval_t aos_lmp_chan_recv_blocking(struct aos_lmp *lmp, struct capref *msg_cap,
                                           struct lmp_recv_msg *recv_buf)
{
    errval_t err;
    while (!lmp_chan_can_recv(&lmp->chan)) {
    }
    while (true) {
        err = lmp_chan_recv(&lmp->chan, recv_buf, msg_cap);
        if (err_is_fail(err) && lmp_err_is_transient(err)) {
            continue;
        } else if (err_is_fail(err)) {
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
 * @param lmp
 * @return errval_t
 */
__attribute__((unused)) static errval_t aos_lmp_recv_msg_blocking(struct aos_lmp *lmp)
{
    errval_t err;
    // receive first message
    struct capref msg_cap;
    struct lmp_recv_msg recv_buf = LMP_RECV_MSG_INIT;

    err = aos_lmp_chan_recv_blocking(lmp, &msg_cap, &recv_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to receive first message part");
        return err;
    }

    if (!lmp->is_busy) {
        err = aos_lmp_recv_first_msg(lmp, &msg_cap, &recv_buf);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to write first message to receive message");
            return err;
        }
    }

    while (lmp->recv_bytes < lmp->recv_msg->payload_bytes + lmp->recv_msg->header_bytes) {
        err = aos_lmp_chan_recv_blocking(lmp, &msg_cap, &recv_buf);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to receive more message parts");
            return err;
        }
        err = aos_lmp_recv_followup_msg(lmp, &recv_buf);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to write follow up message to receive message");
            return err;
        }
    }

    lmp->is_busy = false;
    return err;
}

/**
 * @brief Async recieve
 *
 * @param lmp
 * @return errval_t
 */
static errval_t aos_lmp_recv_msg(struct aos_lmp *lmp)
{
    errval_t err;
    // receive first message
    struct capref msg_cap;
    struct lmp_recv_msg recv_buf = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(&lmp->chan, &recv_buf, &msg_cap);
    if (err_is_fail(err)
        && (lmp_err_is_transient(err) || err_no(err) == LIB_ERR_NO_LMP_MSG)) {
        goto reregister;
    } else if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to receive (non-transient error)\n");
        return err_push(err, LIB_ERR_LMP_CHAN_RECV);
    }


    if (!lmp->is_busy) {
        aos_lmp_recv_first_msg(lmp, &msg_cap, &recv_buf);
    } else {
        aos_lmp_recv_followup_msg(lmp, &recv_buf);
    }

    if (lmp->recv_bytes < lmp->recv_msg->payload_bytes + lmp->recv_msg->header_bytes) {
        goto reregister;
    }

    if (!capref_is_null(msg_cap)) {
        // allocate new receive slot if we received a cap
        err = lmp_chan_alloc_recv_slot(&lmp->chan);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Could not allocate receive slot");
            return err;
        }
    }

    lmp->is_busy = false;

reregister:
    lmp_chan_register_recv(&lmp->chan, get_default_waitset(),
                           MKCLOSURE((void (*)(void *))aos_lmp_recv_msg_handler, lmp));
    return SYS_ERR_OK;
}

errval_t aos_lmp_init_handshake_to_child(struct aos_lmp *child_lmp)
{
    errval_t err;

    struct capref remote_cap;

    while (1) {
        struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;

        err = lmp_endpoint_recv(child_lmp->chan.endpoint, &recv_msg.buf, &remote_cap);
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
    child_lmp->chan.remote_cap = remote_cap;

    size_t payload_size = 0;
    struct aos_lmp_msg *msg;
    char buf[AOS_LMP_MSG_SIZE(payload_size)];
    err = aos_lmp_create_msg_no_pagefault(&msg, AosRpcHandshake, payload_size, NULL,
                                          child_lmp->chan.local_cap,
                                          (struct aos_lmp_msg *)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_lmp_send_msg(child_lmp, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send acknowledgement");
    }
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

static struct lmp_endpoint static_init_ep, static_init_mem_ep;
char STATIC_RPC_BUF[BASE_PAGE_SIZE];
char STATIC_RPC_MEMSRV_BUF[BASE_PAGE_SIZE];

/**
 *  \brief Initialize an aos_lmp struct. Sets up channel to remote endpoint (init)
 *
 *  \param aos_rpc The aos_lmp struct to initialize.
 *
 **/
errval_t aos_lmp_set_recv_endpoint(struct aos_lmp *lmp, struct capref *ret_recv_ep_cap)
{
    // will contain endpoint cap of child
    struct capref ep_cap1;
    errval_t err = slot_alloc(&ep_cap1);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("Failed to allocate slot for child endpoint\n");
        return err;
    }
    lmp_endpoint_set_recv_slot(lmp->chan.endpoint, ep_cap1);
    *ret_recv_ep_cap = ep_cap1;

    return SYS_ERR_OK;
}

errval_t aos_lmp_init_static(struct aos_lmp *lmp, enum aos_rpc_channel_type chan_type)
{
    errval_t err;

    switch (chan_type) {
    case AOS_RPC_BASE_CHANNEL:
        lmp->chan.remote_cap = cap_initep;
        lmp->chan.endpoint = &static_init_ep;
        lmp->buf = STATIC_RPC_BUF;
        break;
    case AOS_RPC_MEMORY_CHANNEL:
        lmp->chan.remote_cap = cap_initmemep;
        lmp->chan.endpoint = &static_init_mem_ep;
        lmp->buf = STATIC_RPC_MEMSRV_BUF;
        break;
    default:
        return LIB_ERR_RPC_INIT_BAD_ARGS;
    }

    // initial state
    thread_mutex_init(&lmp->lock);
    lmp->use_dynamic_buf = false;
    lmp->is_busy = false;

    // MILESTONE 3: register ourselves with init
    /* allocate lmp channel structure */

    /* create local endpoint */
    lmp_chan_init(&lmp->chan);

    lmp->chan.buflen_words = 256;
    err = endpoint_create(lmp->chan.buflen_words, &lmp->chan.local_cap,
                          &lmp->chan.endpoint);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not create endpoint in child \n");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_lmp_init(struct aos_lmp *lmp, struct capref remote_cap)
{
    errval_t err;
    // initial state
    thread_mutex_init(&lmp->lock);
    lmp->is_busy = false;
    lmp->use_dynamic_buf = true;
    lmp->buf = NULL;  // non-static channels do not need the buffer

    err = lmp_chan_accept(&lmp->chan, 256, remote_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to accept incoming channel in aos_lmp_init");
        return err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
    }

    // The channel must be saved to whatever state outside of this function

    /* TODO MILESTONE 3: now we should have a channel with init set up and can
     * use it for the ram allocator */

    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here

    return SYS_ERR_OK;
}

errval_t aos_lmp_initiate_handshake(struct aos_lmp *lmp)
{
    errval_t err;

    err = lmp_chan_send0(&lmp->chan, LMP_SEND_FLAGS_DEFAULT, lmp->chan.local_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send child endpoint cap to init\n");
        return err;
    }

    // allocate receive slot
    err = lmp_chan_alloc_recv_slot(&lmp->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to allocate the receive slot for handshake");
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    // struct capref remote_cap;
    while (1) {
        struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;

        err = lmp_endpoint_recv(lmp->chan.endpoint, &recv_msg.buf, NULL);
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

    // DEBUG_PRINTF("Received handshake\n");

    return SYS_ERR_OK;
}


/**
 * @brief Helper to create a message that should be sent.
 *        This message needs a static buffer with the proper size.
 *
 * @param ret_msg
 * @param msg_type
 * @param payload_size
 * @param payload
 * @param msg_cap
 * @return errval_t
 */
errval_t aos_lmp_create_msg_no_pagefault(struct aos_lmp_msg **ret_msg,
                                         aos_rpc_msg_type_t msg_type, size_t payload_size,
                                         void *payload, struct capref msg_cap,
                                         struct aos_lmp_msg *msg)
{
    size_t header_size = sizeof(struct aos_lmp_msg);

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
 * @brief Helper to create a message that should be sent.
 *        This message is malloced and needs to be freed after it has been used.
 *
 * @param ret_msg
 * @param msg_type
 * @param payload_size
 * @param payload
 * @param msg_cap
 * @return errval_t
 *
 * @note Make sure to free the message after it was used.
 */
errval_t aos_lmp_create_msg(struct aos_lmp_msg **ret_msg, aos_rpc_msg_type_t msg_type,
                            size_t payload_size, void *payload, struct capref msg_cap)
{
    size_t header_size = sizeof(struct aos_lmp_msg);
    struct aos_lmp_msg *msg = malloc(
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
 * @param lmp
 * @param msg
 *
 * @return
 */
errval_t aos_lmp_send_msg(struct aos_lmp *lmp, struct aos_lmp_msg *msg)
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
            err = lmp_chan_send(&lmp->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, 4, buf[0],
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

    err = SYS_ERR_OK;
    do {
        switch (DIVIDE_ROUND_UP(remaining, sizeof(uint64_t))) {
        case 0:
            if (remaining == 0) {
                err = SYS_ERR_OK;
                break;
            }
            // continue in case 1 for leftover stuff?
        case 1:
            err = lmp_chan_send1(&lmp->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, buf[0]);
            break;
        case 2:
            err = lmp_chan_send2(&lmp->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, buf[0],
                                 buf[1]);
            break;
        case 3:
            err = lmp_chan_send3(&lmp->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, buf[0],
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

errval_t aos_lmp_register_recv(struct aos_lmp *lmp, process_msg_func_t process_msg_func)
{
    errval_t err;

    lmp->process_msg_func = process_msg_func;

    err = lmp_chan_alloc_recv_slot(&lmp->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    err = lmp_chan_register_recv(
        &lmp->chan, get_default_waitset(),
        MKCLOSURE((void (*)(void *))aos_lmp_recv_msg_handler, lmp));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to register receive function");
        return err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
    }

    return SYS_ERR_OK;
}

errval_t aos_lmp_reregister_recv(struct aos_lmp *lmp, process_msg_func_t process_msg_func)
{
    errval_t err = lmp_chan_deregister_recv(&lmp->chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to deregister channel\n");
        return err_push(err, LIB_ERR_CHAN_DEREGISTER_RECV);
    }

    return aos_lmp_register_recv(lmp, process_msg_func);
}

errval_t aos_lmp_call(struct aos_lmp *lmp, struct aos_lmp_msg *msg)
{
    thread_mutex_lock(&lmp->lock);
    errval_t err = SYS_ERR_OK;

    // send message
    err = aos_lmp_send_msg(lmp, msg);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        goto unwind;
    }

    err = aos_lmp_recv_msg_blocking(lmp);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive message");
        // TODO remove abort
        goto unwind;
    }


unwind:
    thread_mutex_unlock(&lmp->lock);
    return err;
}

errval_t aos_lmp_setup_local_chan(struct aos_lmp *lmp, struct capref cap_ep)
{
    // setup endpoint of init
    lmp_chan_init(&lmp->chan);
    errval_t err = lmp_endpoint_create_in_slot(512, cap_ep, &lmp->chan.endpoint);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed create endpoint in init process");
        return err;
    }

    // TODO review if this line is necessary
    lmp->chan.buflen_words = 256;

    return SYS_ERR_OK;
}

/**
 * @brief This helper function sets up an LMP channel to some remote endpoint without
 * facilities to receive messages. This is useful if we want to send a one off message to
 * some endpoint that we know is listening.
 *
 * @param lmp pointer to the LMP instance to initialize
 * @param remote_cap capref to the LMP endpoint cap of the recipient (needs to be on the
 * same core)
 *
 * @returns error value
 */
static errval_t aos_lmp_init_fire_and_forget(struct aos_lmp *lmp, struct capref remote_cap)
{
    struct capability cap;
    errval_t err = cap_direct_identify(remote_cap, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to identify remote cap. Is it really on the same core?");
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    if (cap.type != ObjType_EndPointLMP) {
        DEBUG_PRINTF("Remote cap is not an LMP endpoint capability\n");
        return MON_ERR_WRONG_CAP_TYPE;
    }

    thread_mutex_init(&lmp->lock);
    lmp->is_busy = false;
    lmp->use_dynamic_buf = true;
    lmp->buf = NULL;  // non-static channels do not need the buffer

    // set up the channel without facilities to receive
    lmp_chan_init(&lmp->chan);
    lmp->chan.local_cap = NULL_CAP;
    lmp->chan.remote_cap = remote_cap;
    lmp->chan.connstate = LMP_CONNECTED;

    return SYS_ERR_OK;
}

errval_t aos_lmp_parent_init(struct aos_lmp *lmp)
{
    lmp->is_busy = false;
    lmp->buf = malloc(BASE_PAGE_SIZE);
    if (!lmp->buf) {
        DEBUG_PRINTF("failed to allocate lmp buffer\n");
        return LIB_ERR_MALLOC_FAIL;
    }
    thread_mutex_init(&lmp->lock);

    return SYS_ERR_OK;
}

/**
 * @brief Sends an LMP message to the endpoint at the remote capability over a temporary
 * channel.
 *
 * @param remote_cap LMP ndpoint capability to the recipient (needs to be on the same core)
 * @param msg Message to send
 *
 * @returns error value
 *
 * @note The message is not freed in this function.
 */
errval_t aos_lmp_fire_and_forget(struct capref remote_cap, struct aos_lmp_msg *msg)
{
    errval_t err;

    struct aos_lmp lmp;
    err = aos_lmp_init_fire_and_forget(&lmp, remote_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to set up fire and forget channel");
        return err_push(err, LIB_ERR_LMP_INIT_FNF);
    }

    err = aos_lmp_send_msg(&lmp, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to send message over fire and forget channel");
        return err_push(err, LIB_ERR_LMP_CHAN_SEND);
    }

    return SYS_ERR_OK;
}
