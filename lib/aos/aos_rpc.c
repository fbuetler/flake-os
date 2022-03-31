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

    while (transferred_size < total_bytes && ceil((double)(total_bytes-transferred_size)/ (double)sizeof(uint64_t)) >= 4) {
        // size_t remaining = total_bytes - transferred_size;
        // if (remaining < LMP_MSG_LENGTH_BYTES) {
        //     memset(buf + remaining, 0, (LMP_MSG_LENGTH_BYTES - remaining));
        // }

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
    if(transferred_size >= total_bytes)
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
                printf("inside msg_send. Should not get here \n");
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

/**
 * @brief handler for handshake messages
 *
 * @param msg
 */
static void aos_process_handshake(struct aos_rpc_msg *msg)
{
    printf("Handshake ACK\n");
    free(msg);
}

/**
 * @brief default handler for number messages
 *
 * @param msg
 */
static void aos_process_number(struct aos_rpc_msg *msg)
{
    printf("received number: %d\n", *((uint64_t *)msg->payload));
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
    printf("received string: %s\n", msg->payload);
    free(msg);
}


/**
 * @brief default handler for ram cap response messages
 *
 * @param msg
 */
static void aos_process_ram_cap_response(struct aos_rpc_msg *msg)
{
    printf("received ram cap response\n");
    // TODO got the ram cap

    struct capref *ret_cap = ((struct capref **)msg->payload)[0];
    printf("roundtrip ret addr %lx\n", ret_cap);

    printf("receive ram cap\n");
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, msg->cap);
    debug_printf("%.*s\n", 256, buf1);

    *ret_cap = msg->cap;
    free(msg);
}


/**
 * @brief default handler for spawn response messages
 *
 * @param msg
 */
static void aos_process_spawn_response(struct aos_rpc_msg *msg)
{
    domainid_t assigned_pid = *((domainid_t *)msg->payload);
    printf("spawned process: %d\n", assigned_pid);

    domainid_t *pid = (domainid_t *)((char *)msg->payload + sizeof(domainid_t));

    *pid = assigned_pid;
    free(msg);
}

/**
 * @brief sets the default handlers for some message types
 *
 * @param rpc
 * @return errval_t
 */
errval_t aos_rpc_process_msg(struct aos_rpc *rpc)
{
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
    case RamCapResponse:
        aos_process_ram_cap_response(rpc->recv_msg);
        break;
    case SpawnResponse:
        aos_process_spawn_response(rpc->recv_msg);
        break;
    default:
        printf("received unknown message type\n");
        free(rpc->recv_msg);
        break;
    }
    // TODO: free msg
    return SYS_ERR_OK;
}

errval_t aos_rpc_recv_msg_handler(void *args)
{
    errval_t err;
    struct aos_rpc *rpc = (struct aos_rpc *)args;

    // receive first message
    struct capref msg_cap;
    struct lmp_recv_msg recv_buf = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(&rpc->chan, &recv_buf, &msg_cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        goto reregister;
    } else if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_RECV);
    }

    if (!capref_is_null(msg_cap)) {
        // alloc for next time
        err = lmp_chan_alloc_recv_slot(&rpc->chan);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to allocated receive slot");
            err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
            goto reregister;
        }
    }

    if (!rpc->is_busy) {
        // setup rpc state with new message and set to busy

        struct aos_rpc_msg *tmp_msg = (struct aos_rpc_msg *)recv_buf.words;
        size_t total_bytes = tmp_msg->header_bytes + tmp_msg->payload_bytes;

        size_t recv_bytes = MIN(LMP_MSG_LENGTH_BYTES, total_bytes);

        //printf("Received bytes: %zu total_bytes: %zu", recv_bytes, total_bytes);

        // allocate space for return message, copy current message already to it
        rpc->recv_msg = malloc(total_bytes);
        if (!rpc->recv_msg) {
            DEBUG_PRINTF("Malloc inside aos_rpc_recv_msg_handler for ret_msg failed \n");
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(rpc->recv_msg, tmp_msg, recv_bytes);
        rpc->recv_bytes = recv_bytes;
        rpc->is_busy = true;
        rpc->recv_msg->cap = msg_cap;
    } else {
        size_t total_bytes = rpc->recv_msg->header_bytes + rpc->recv_msg->payload_bytes;
        size_t remaining_bytes = total_bytes - rpc->recv_bytes;
        //printf("Recv: total bytes: %zu msg_header: %hu msg_payload %d , recv_bytes: %zu \n", total_bytes,  rpc->recv_msg->header_bytes,  rpc->recv_msg->payload_bytes, rpc->recv_bytes);

        size_t copy_bytes = MIN(remaining_bytes, LMP_MSG_LENGTH_BYTES);
        //printf("Copy bytes: %zu \n", copy_bytes);
        //printf("buffer content: %s \n", (char*)recv_buf.words);
        memcpy(((char *)rpc->recv_msg) + rpc->recv_bytes, recv_buf.words, copy_bytes);
        rpc->recv_bytes += copy_bytes;
    }

    if (rpc->recv_bytes < rpc->recv_msg->payload_bytes + rpc->recv_msg->header_bytes) {
        goto reregister;
    }

    rpc->is_busy = false;
    rpc->process_msg_func(rpc);

reregister:
    lmp_chan_register_recv(&rpc->chan, get_default_waitset(),
                           MKCLOSURE((void (*)(void *))aos_rpc_recv_msg_handler, args));

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    // round to next uintptr_t so that send_msg doesn't read beyond buffer limit
    size_t struct_size = ROUND_UP(sizeof(struct aos_rpc_msg) + sizeof(num), sizeof(uintptr_t));
    struct aos_rpc_msg *msg = malloc(struct_size);

    if (!msg) {
        DEBUG_PRINTF("Malloc failed in aos_rpc_send_number \n");
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

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err;

    size_t len = strlen(string);

    size_t struct_size = ROUND_UP(sizeof(struct aos_rpc_msg) + len, sizeof(uintptr_t));
    struct aos_rpc_msg *msg = malloc(struct_size);

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = len;
    msg->message_type = SendString;
    msg->cap = NULL_CAP;
    memcpy(msg->payload, string, len);

    //printf("msg sizes header: %lu payload size: %zu \n", sizeof(struct aos_rpc_msg), len);
    //printf("Payload before sending: %s \n", msg->payload);

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
    errval_t err;
    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.

    // send memory allocation request to init

    printf("get ram request: size: 0x%lx alignment: 0x%lx\n", bytes, alignment);
    printf("initial ret addr %lx\n", ret_cap);
    size_t payload_size = 3 * sizeof(size_t);

    size_t struct_size = ROUND_UP(sizeof(struct aos_rpc_msg) + sizeof(size_t) * 3, sizeof(uintptr_t));
    struct aos_rpc_msg *msg  = malloc(struct_size);

    ((size_t *)msg->payload)[0] = bytes;
    ((size_t *)msg->payload)[1] = alignment;
    ((struct capref **)msg->payload)[2] = ret_cap;

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = payload_size;
    msg->message_type = RamCapRequest;
    msg->cap = NULL_CAP;

    err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    err = event_dispatch(get_default_waitset());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in event_dispatch");
        return err;
    }

    // read result

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

    size_t payload_size = strlen(cmdline) + 1;

    size_t struct_size = ROUND_UP(sizeof(struct aos_rpc_msg) + payload_size, sizeof(uintptr_t));
    struct aos_rpc_msg *msg  = malloc(struct_size);

    memcpy(msg->payload, cmdline, payload_size);

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = payload_size;
    msg->message_type = SpawnRequest;
    msg->cap = NULL_CAP;

    errval_t err = aos_rpc_send_msg(rpc, msg);
    assert(err_is_ok(err));
    return event_dispatch(get_default_waitset());
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

        lmp_endpoint_set_recv_slot(init_rpc->chan.endpoint, memeater_endpoint_cap);
        err = lmp_endpoint_recv(init_rpc->chan.endpoint, &recv_msg.buf,
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


    printf("init local \n");
    char buf0[256];
    debug_print_cap_at_capref(buf0, 256, child_rpc->chan.local_cap);
    debug_printf("%.*s\n", 256, buf0);

    printf("init remote \n");
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, child_rpc->chan.remote_cap);
    debug_printf("%.*s\n", 256, buf1);

    struct aos_rpc_msg handshake_msg;
    handshake_msg.header_bytes = sizeof(struct aos_rpc_msg);
    handshake_msg.message_type = Handshake;
    handshake_msg.payload_bytes = 0;
    handshake_msg.cap = child_rpc->chan.local_cap;

    printf("child rpc: %p \n", child_rpc);
    err = aos_rpc_send_msg(child_rpc, &handshake_msg);
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

    // initial state
    aos_rpc->is_busy = false;

    // MILESTONE 3: register ourselves with init
    /* allocate lmp channel structure */

    /* create local endpoint */
    lmp_chan_init(&aos_rpc->chan);

    struct lmp_endpoint *ep = malloc(sizeof(struct lmp_endpoint));
    assert(ep);

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

    err = aos_rpc_register_recv(aos_rpc, aos_rpc_process_msg);
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


    err = event_dispatch(get_default_waitset());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in event dispatch\n");
        abort();
    }

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
