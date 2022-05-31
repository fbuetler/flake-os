#include <aos/nameserver.h>
#include <aos/aos_rpc.h>
#include <serialio/serialio.h>

void aos_rpc_init_from_ump(struct aos_rpc *rpc, struct aos_ump *chan)
{
    rpc->u.ump = *chan;
    rpc->is_lmp = false;
}

void aos_rpc_init_from_lmp(struct aos_rpc *rpc, struct aos_lmp *chan)
{
    rpc->u.lmp = *chan;
    rpc->is_lmp = true;
}


/**
 * @brief Synchronously performs an RPC call over LMP or UMP depending on the channel
 *
 * @param rpc RPC binding (only non-static channels)
 * @param msg RPC message to send
 * @param retmsg pointer to where we should write the response message
 *
 * @returns error value
 *
 * @note This function will perform mallocs. Therefore, channels with a
 * no-pagefault-requirement must not use this functions. If you try, this function will
 * fail.
 *
 * @note The payload in the return message needs to be freed.
 */
errval_t aos_rpc_call(struct aos_rpc *rpc, struct aos_rpc_msg msg,
                      struct aos_rpc_msg *retmsg)
{
    errval_t err = SYS_ERR_OK;

    if (rpc->is_lmp) {
        struct aos_lmp *lmp = &rpc->u.lmp;
        if (!lmp->dynamic_channel) {
            DEBUG_PRINTF("aos_rpc_call only works for dynamic channels\n");
            return ERR_INVALID_ARGS;
        }

        struct aos_lmp_msg *lmp_msg;
        // First, try to create the message in the static buffer
        err = aos_lmp_create_msg_no_pagefault(&rpc->u.lmp, &lmp_msg, msg.type, msg.bytes,
                                              msg.payload, msg.cap,
                                              (struct aos_lmp_msg *)lmp->buf);
        if (err_is_fail(err)) {
            // retry to create message with dynamic buffer
            err = aos_lmp_create_msg(lmp, &lmp_msg, msg.type, msg.bytes, msg.payload,
                                     msg.cap);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to create message");
                return err;
            }
        }
        err = aos_lmp_call(lmp, lmp_msg);
        if (lmp->use_dynamic_buf) {
            free(lmp_msg);
        }
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to send lmp message");
            return err;
        }

        retmsg->bytes = lmp->recv_msg->payload_bytes;
        retmsg->type = lmp->recv_msg->message_type;
        retmsg->cap = lmp->recv_msg->cap;

        // Allocate buffer for response and fill it
        void *payload_buf = malloc(retmsg->bytes);
        if (payload_buf == NULL) {
            DEBUG_PRINTF("Failed to allocate buffer for response\n");
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(payload_buf, rpc->u.lmp.recv_msg->payload, retmsg->bytes);
        retmsg->payload = payload_buf;

        // Now that we have copied everything we can clean up the received message
        aos_lmp_msg_free(lmp);

        if (!capcmp(retmsg->cap, NULL_CAP)) {
            err = lmp_chan_alloc_recv_slot(&lmp->chan);
            if (err_is_fail(err)) {
                free(payload_buf);
                DEBUG_ERR(err, "failed to allocated receive slot");
                err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
                return err;
            }
        }
    } else {
        if (!capref_is_null(msg.cap)) {
            // TODO-refactor
        }
        return aos_ump_call(&rpc->u.ump, msg.type, msg.payload, msg.bytes, &retmsg->type,
                            &retmsg->payload, &retmsg->bytes);
    }

    return err;
}

errval_t aos_rpc_bind(struct aos_rpc *init_lmp, struct aos_rpc *rpc, coreid_t core,
                      enum aos_rpc_service service)
{
    rpc->is_lmp = false;
    errval_t err = aos_ump_bind(&init_lmp->u.lmp, &rpc->u.ump, core, service);
    return err;
}

errval_t aos_rpc_send_errval(struct aos_rpc *rpc, errval_t err_send)
{
    errval_t err;
    struct aos_rpc_msg msg = { .type = AosRpcErrvalResponse,
                               .payload = (char *)&err_send,
                               .bytes = sizeof(errval_t),
                               .cap = NULL_CAP };

    if (rpc->is_lmp) {
        char buf[AOS_LMP_MSG_SIZE(sizeof(errval_t))];
        struct aos_lmp_msg *lmp_msg;
        err = aos_lmp_create_msg_no_pagefault(&rpc->u.lmp, &lmp_msg, msg.type, msg.bytes,
                                              msg.payload, msg.cap,
                                              (struct aos_lmp_msg *)buf);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to create message");
            return err_push(err, LIB_ERR_LMP_MSG_CREATE);
        }
        err = aos_lmp_send_msg(&rpc->u.lmp, lmp_msg);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to send lmp message");
            return err;
        }
    } else {
        err = aos_ump_send(&rpc->u.ump, msg.type, msg.payload, msg.bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to send ump message");
            return err;
        }
    }

    return SYS_ERR_OK;
}

void aos_rpc_process_client_request(struct aos_rpc_msg *request,
                                    struct aos_rpc_msg *response)
{
    // DEBUG_PRINTF("Received a message from a client\n");
    struct nameservice_rpc_msg *msg = (struct nameservice_rpc_msg *)request->payload;

    response->type = AosRpcServerResponse;

    // call handler
    msg->handler(msg->st, msg->message, msg->bytes, (void **)&response->payload,
                 &response->bytes, request->cap, &response->cap);
}

errval_t aos_rpc_send_number(struct aos_rpc *aos_rpc, uintptr_t num)
{
    errval_t err;

    struct aos_rpc_msg request = { .type = AosRpcSendNumber,
                                   .payload = (char *)&num,
                                   .bytes = sizeof(num),
                                   .cap = NULL_CAP };

    struct aos_rpc_msg response;

    err = aos_rpc_call(aos_rpc, request, &response);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    return SYS_ERR_OK;
}

/**
 * @brief Request a new ram capability of a certain size and alignment from the memory
 * server
 *
 * @param rpc LMP-Binding to the memory server (UMP is not supported as per our design
 * decision)
 * @param bytes requested size for the memory region
 * @param alignment requested alignment for the memory region
 * @param ret_cap pointer which will point to the received cap after successful execution
 * of this function
 * @param ret_bytes pointer to the actual size of the received memory region
 *
 * @returns error value
 *
 * @note This is a crucial code path to obtain new memory. Therefore, everything in this
 * function and the functions called within MUST NOT incurr any page faults or other
 * memory requests.
 *
 * @note It is our design decision that memory can only be requested via LMP call to the
 * core local memory server. Therefore, this function only performs an aos_lmp_call
 * instead of an aos_rpc_call. Since no other RPC call has a no-page-fault requirement,
 * this allows for some simplifications in aos_rpc_call.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    if (!rpc->is_lmp) {
        DEBUG_PRINTF("Our system does not support transferring RAM caps from other "
                     "cores\n");
        return ERR_INVALID_ARGS;
    }

    errval_t err = lmp_chan_alloc_recv_slot(&rpc->u.lmp.chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    // Setup request message
    size_t payload_size = sizeof(struct ram_cap_request);
    struct ram_cap_request payload = { .bytes = bytes, .alignment = alignment };
    char buf[AOS_LMP_MSG_SIZE(payload_size)];

    struct aos_lmp_msg *req;
    err = aos_lmp_create_msg_no_pagefault(&rpc->u.lmp, &req, AosRpcRamCapRequest, payload_size,
                                          (void *)&payload, NULL_CAP,
                                          (struct aos_lmp_msg *)buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to create RAM cap request message");
        return err_push(err, LIB_ERR_LMP_MSG_CREATE);
    }

    err = aos_lmp_call(&rpc->u.lmp, req);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to perform RAM cap request");
        return err_push(err, LIB_ERR_LMP_CALL);
    }

    struct aos_lmp_msg *resp = rpc->u.lmp.recv_msg;

    if (resp->message_type != AosRpcRamCapResponse) {
        DEBUG_PRINTF("message type is not RamCapResponse, it's %d\n", resp->message_type);
        return LIB_ERR_RPC_UNEXPECTED_MSG_TYPE;
    }

    *ret_cap = resp->cap;

    if (capref_is_null(*ret_cap)) {
        DEBUG_PRINTF("Failed to get a ram cap\n");
        return LIB_ERR_LMP_CALL;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *aos_rpc, const char *string)
{
    errval_t err;

    struct aos_rpc_msg request = { .type = AosRpcSendString,
                                   .payload = (void *)string,
                                   .bytes = strlen(string),
                                   .cap = NULL_CAP };

    struct aos_rpc_msg response;

    err = aos_rpc_call(aos_rpc, request, &response);
    free(response.payload);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send string\n");
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;

    struct aos_rpc_msg request
        = { .type = AosRpcSerialReadChar, .payload = NULL, .bytes = 0, .cap = NULL_CAP };
    struct aos_rpc_msg response;

    err = aos_rpc_call(rpc, request, &response);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed serial putchar request");
        return err;
    }

    struct serialio_response *serial_response
        = (struct serialio_response *)response.payload;

    if (serial_response->response_type == SERIAL_IO_NO_DATA) {
        free(response.payload);
        return LPUART_ERR_NO_DATA;
    } else {
        *retc = serial_response->c;
        free(response.payload);
    }


    return err;
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    errval_t err = SYS_ERR_OK;

    struct aos_rpc_msg request = { .type = AosRpcSerialWriteChar,
                                   .payload = &c,
                                   .bytes = sizeof(char),
                                   .cap = NULL_CAP };

    struct aos_rpc_msg response;

    err = aos_rpc_call(rpc, request, &response);
    free(response.payload);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed serial putchar request");
        return err;
    }

    return err;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    // TODO (M5): implement name lookup for process given a process id
    errval_t err;

    struct aos_rpc_msg request = { .type = AosRpcPid2Name,
                                   .payload = (void *)&pid,
                                   .bytes = sizeof(domainid_t),
                                   .cap = NULL_CAP };

    struct aos_rpc_msg response;

    // TODO-refactor: free lmp->recv_msg
    err = aos_rpc_call(rpc, request, &response);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed lmp getname request");
        return err;
    }

    char *assigned_name = response.payload;

    if (*assigned_name == 0) {
        return SPAWN_ERR_PID_NOT_FOUND;
    }

    size_t name_len = strlen(assigned_name);
    *name = (char *)malloc(name_len + 1);
    if (!*name) {
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(*name, assigned_name, name_len + 1);

    return SYS_ERR_OK;
}

errval_t aos_rpc_kill_process(struct aos_rpc *rpc, const domainid_t pid)
{
    errval_t err;

    struct aos_rpc_msg request = { .type = AosRpcKillRequest,
                                   .payload = (void*)&pid,
                                   .bytes = sizeof(domainid_t),
                                   .cap = NULL_CAP };

    struct aos_rpc_msg response;
    err = aos_rpc_call(rpc, request, &response);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send aos_rpc_kill_process message \n");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    errval_t err;

    size_t cmdline_len = strlen(cmdline);
    size_t payload_size = sizeof(coreid_t) + cmdline_len + 1;
    char *payload = (char *)malloc(payload_size);
    if (payload == NULL) {
        DEBUG_PRINTF("Failed to allocate spawn message payload\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    *(coreid_t *)payload = core;
    memcpy(payload + sizeof(coreid_t), cmdline, cmdline_len + 1);

    // TODO-refactor: now only static-sized bufs work at the moment!
    struct aos_rpc_msg request = { .type = AosRpcSpawnRequest,
                                   .payload = payload,
                                   .bytes = payload_size,
                                   .cap = NULL_CAP };

    struct aos_rpc_msg response;

    err = aos_rpc_call(rpc, request, &response);
    free(payload);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to send and receive spawn request and response");
        return err_push(err, LIB_ERR_RPC_CALL);
    }

    DEBUG_PRINTF("Received spawn response\n");

    domainid_t assigned_pid = *((domainid_t *)response.payload);
    DEBUG_PRINTF("spawned process with PID 0x%x\n", assigned_pid);
    *newpid = assigned_pid;

    free(response.payload);

    return SYS_ERR_OK;
}

/**
 *
 * @brief RPC call to get all process pids. pids is malloced and needs to be freed by caller
 *
 * @param lmp
 * @param pids 
 * @param pid_count
 * @return errval_t
 * 
 * @note The pointer to the buffer containing the pids needs to be freed by the caller.
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    // DEBUG_PRINTF("get all pids!\n");
    //  TODO (M5): implement process id discovery
    errval_t err;

    struct aos_rpc_msg request
        = { .type = AosRpcGetAllPids, .payload = NULL, .bytes = 0, .cap = NULL_CAP };

    struct aos_rpc_msg response;

    err = aos_rpc_call(rpc, request, &response);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    *pid_count = *((size_t *)response.payload);

    *pids = malloc(*pid_count * sizeof(domainid_t));
    memcpy(*pids, response.payload + sizeof(size_t), *pid_count * sizeof(domainid_t));

    free(response.payload);

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
    return get_init_mem_rpc();
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
    return get_serial_rpc();
}
