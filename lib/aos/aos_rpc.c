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
#include <spawn/spawn.h>

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
    while (total_bytes - transferred_size >= 4 * sizeof(uint64_t)) {
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

    size_t remaining = total_bytes - transferred_size;
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
}

/**
 * @brief default handler for number messages
 *
 * @param msg
 */
static void aos_process_number(struct aos_rpc_msg *msg)
{
    printf("received number: %d\n", *((uint64_t *)msg->payload));
}

/**
 * @brief default handler for string messages
 *
 * @param msg
 */
static void aos_process_string(struct aos_rpc_msg *msg)
{
    printf("received string: %s\n", msg->payload);
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
}

static void aos_process_serial_read_response(struct aos_rpc_msg *msg){
    //void *ptr = ((void **) msg->payload)[0];
    char c = (char) ((uint64_t*) msg->payload)[1];

    //char c = ((size_t)buf) >> (63-8);

    //buf = (char *)((size_t)buf ^ ((size_t)c << (63 - 8)));
    //*buf = c; 
    printf("got serial read response: '%c'\n", c);
}

errval_t aos_rpc_process_msg(struct aos_rpc *rpc) {
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
    case SerialReadCharResponse:
        aos_process_serial_read_response(rpc->recv_msg);
        break;
    default:
        printf("received unknown message type\n");
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

        // printf("Received bytes: %zu total_bytes: %zu", recv_bytes, total_bytes);

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
        // printf("Recv: total bytes: %zu msg_header: %hu msg_payload %d , recv_bytes: %zu
        // \n", total_bytes,  rpc->recv_msg->header_bytes,  rpc->recv_msg->payload_bytes,
        // rpc->recv_bytes);

        size_t copy_bytes = MIN(remaining_bytes, LMP_MSG_LENGTH_BYTES);
        // printf("Copy bytes: %zu \n", copy_bytes);
        // printf("buffer content: %s \n", (char*)recv_buf.words);
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
    errval_t err;
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, SendNumber, sizeof(num), (void *)&num, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = aos_rpc_send_msg(rpc, msg);
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
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, SendString, len, (void *)string, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    // printf("msg sizes header: %lu payload size: %zu \n", sizeof(struct aos_rpc_msg),
    // len); printf("Payload before sending: %s \n", msg->payload);

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

    printf("get ram request: size: 0x%lx alignment: 0x%lx\n", bytes, alignment);
    printf("initial ret addr %lx\n", ret_cap);

    size_t payload_size = 3 * sizeof(size_t);
    void *payload = malloc(payload_size);
    ((size_t *)payload)[0] = bytes;
    ((size_t *)payload)[1] = alignment;
    ((struct capref **)payload)[2] = ret_cap;

    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, RamCapRequest, payload_size, (void *)payload, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

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
    size_t payload_size = sizeof(char *);

    struct aos_rpc_msg *msg  = malloc(sizeof(struct aos_rpc_msg) + payload_size);
    ((char**)msg->payload)[0] = retc;

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = payload_size;
    msg->message_type = SerialReadChar;
    msg->cap = NULL_CAP;

    errval_t err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }
    
    err = event_dispatch(get_default_waitset());
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Error in event_dispatch");
        return err;
    }
    err = event_dispatch(get_default_waitset());
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Error in event_dispatch");
        return err;
    }
    
    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.
    size_t payload_size = sizeof(size_t);

    struct aos_rpc_msg *msg  = malloc(sizeof(struct aos_rpc_msg) + payload_size);
    msg->payload[0] = c;

    msg->header_bytes = sizeof(struct aos_rpc_msg);
    msg->payload_bytes = payload_size;
    msg->message_type = SerialWriteChar;
    msg->cap = NULL_CAP;

    errval_t err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }
    
    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    // TODO (M5): implement spawn new process rpc
    errval_t err;

    size_t payload_size = strlen(cmdline);
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg(&msg, SpawnRequest, payload_size, cmdline, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    printf("cmd in msg: %s\n", msg->payload);

    err = aos_rpc_send_msg(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }
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

    char buf0[256];
    debug_print_cap_at_capref(buf0, 256, child_rpc->chan.local_cap);
    debug_printf("local: %.*s\n", 256, buf0);
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, child_rpc->chan.remote_cap);
    debug_printf("remote %.*s\n", 256, buf1);

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

    /* set receive handler */
    /*err = lmp_chan_register_recv(&aos_rpc->chan, get_default_waitset(),
                                 MKCLOSURE(aos_handshake_recv_closure, &aos_rpc->chan));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not register recv handler in child \n");
        return err;
    }*/

    /* send local ep to init */
    err = lmp_chan_send0(&aos_rpc->chan, LMP_SEND_FLAGS_DEFAULT, aos_rpc->chan.local_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send child endpoint cap to init\n");
        return err;
    }

    err = aos_rpc_register_recv(aos_rpc, aos_rpc_process_msg);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Could not register recv handler in child \n");
        return err;
    }

    err = event_dispatch(get_default_waitset());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error in event dispatch\n");
        abort();
    }

    char buf0[256];
    debug_print_cap_at_capref(buf0, 256, aos_rpc->chan.local_cap);
    debug_printf("local: %.*s\n", 256, buf0);
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, aos_rpc->chan.remote_cap);
    debug_printf("remote: %.*s\n", 256, buf1);

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
    return get_init_rpc();
    return NULL;
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
