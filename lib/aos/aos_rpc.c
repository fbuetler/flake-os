#include <aos/aos_rpc.h>

void rpc_init_from_ump(struct aos_rpc *rpc, struct ump_chan *chan){
    rpc->u.ump = *chan;
    rpc->is_lmp = false;
}

void rpc_init_from_lmp(struct aos_rpc *rpc, struct aos_lmp *chan){
    rpc->u.lmp = *chan;
    rpc->is_lmp = true;
}

// TODO-refactor: currently only for static bufs if lmp (no too large messages)
errval_t rpc_call(struct aos_rpc *rpc, struct rpc_msg msg, struct rpc_msg *retmsg, bool is_dynamic){
    errval_t err = SYS_ERR_OK;

    // TODO-refactor: dynamic sizes
    char buf[1024];
    if(rpc->is_lmp){
        struct aos_lmp_msg *lmp_msg;
        if(!is_dynamic){
            err = aos_lmp_create_msg_no_pagefault(&lmp_msg, msg.type, msg.bytes, msg.payload, msg.cap, (struct aos_lmp_msg *)buf);
        }else{
            err = aos_lmp_create_msg(&lmp_msg, msg.type, msg.bytes, msg.payload, msg.cap);
        }
        if(err_is_fail(err)){
            DEBUG_ERR(err, "failed to create message");
            return err;
        }
        err = aos_lmp_call(&rpc->u.lmp, lmp_msg, is_dynamic);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "failed to send lmp message");
            return err;
        }

        retmsg->payload = rpc->u.lmp.recv_msg->payload;
        retmsg->bytes = rpc->u.lmp.recv_msg->payload_bytes;
        retmsg->type = rpc->u.lmp.recv_msg->message_type;
        retmsg->cap = rpc->u.lmp.recv_msg->cap;

        if(!capcmp(retmsg->cap, NULL_CAP)){
            err = lmp_chan_alloc_recv_slot(&rpc->u.lmp.chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to allocated receive slot");
                err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
                return err;
            }  
        }

    } else {
        if(!capcmp(msg.cap, NULL_CAP)) {
            // TODO-refactor 
        }
        return ump_call(&rpc->u.ump, msg.type, msg.payload, msg.bytes, &retmsg->type, &retmsg->payload, &retmsg->bytes);
    }

    return err;
}

errval_t rpc_bind(struct aos_lmp *init_lmp, struct aos_rpc *rpc, coreid_t core,
                  enum aos_rpc_service service){
    rpc->is_lmp = false;
    errval_t err = ump_bind(init_lmp, &rpc->u.ump, core, service);
    return err;
}

errval_t aos_rpc_send_number(struct aos_rpc *aos_rpc, uintptr_t num)
{
    errval_t err;

    struct rpc_msg request = {
        .type = AosRpcSendNumber,
        .payload = (char *)&num,
        .bytes = sizeof(num),
        .cap = NULL_CAP
    };

    struct rpc_msg response;

    err = rpc_call(aos_rpc, request, &response, false);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    errval_t err = lmp_chan_alloc_recv_slot(&rpc->u.lmp.chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        abort();
    }  


    size_t payload_size = 2 * sizeof(size_t);
    char payload[payload_size];
    ((size_t *)payload)[0] = bytes;
    ((size_t *)payload)[1] = alignment;

    struct rpc_msg request = {
        .type = AosRpcRamCapRequest,
        .payload = payload,
        .bytes = payload_size,
        .cap = NULL_CAP
    };

    struct rpc_msg response;

    err = rpc_call(rpc, request, &response, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

    err = lmp_chan_alloc_recv_slot(&rpc->u.lmp.chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocated receive slot");
        err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        abort();
    }

    if(response.type != AosRpcRamCapResponse){
        DEBUG_PRINTF("message type is not RamCapResponse, it's %d\n", response.type);
    }

    *ret_cap = response.cap;

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *aos_rpc, const char *string)
{
    errval_t err;

    /*
    size_t payload_size = strlen(string);
    struct aos_lmp_msg *msg;
    err = aos_lmp_create_msg(&msg, AosRpcSendString, payload_size, (void *)string, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }
    */

    struct rpc_msg request = {
        .type = AosRpcSendString,
        .payload = (void *)string,
        .bytes = strlen(string),
        .cap = NULL_CAP
    };

    struct rpc_msg response;
    
    err = rpc_call(aos_rpc, request, &response, true);

    //err = aos_lmp_send_msg(lmp, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send string\n");
        // TODO still required?
        //free(msg);
        return err_push(err, LIB_ERR_RPC_SEND);
    }

    // TODO still required?
    //free(msg);

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;

    struct rpc_msg request = {
        .type = AosRpcSerialReadChar,
        .payload = NULL,
        .bytes = 0,
        .cap = NULL_CAP
    };
    struct rpc_msg response;

    err = rpc_call(rpc, request, &response, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed serial putchar request");
        return err;
    }

    *retc = *response.payload;

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    errval_t err = SYS_ERR_OK;

    struct rpc_msg request = {
        .type = AosRpcSerialWriteChar,
        .payload = &c,
        .bytes = sizeof(char),
        .cap = NULL_CAP
    };

    struct rpc_msg response;

    err = rpc_call(rpc, request, &response, false);
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

    struct rpc_msg request={
        .type = AosRpcPid2Name,
        .payload = (void *)&pid,
        .bytes = sizeof(domainid_t),
        .cap = NULL_CAP
    };

    struct rpc_msg response;

    // TODO-refactor: free lmp->recv_msg 
    err = rpc_call(rpc, request, &response, true);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed lmp getname request");
        return err;
    }

    char *assigned_name = response.payload;

    if(*assigned_name == 0){
        DEBUG_PRINTF("no pid assigned to this!\n");
    }

    size_t name_len = strlen(assigned_name);
    *name = (char *) malloc(name_len+1);
    if(!*name){
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(*name, assigned_name, name_len + 1);

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    // TODO (M5): implement spawn new process lmp
    errval_t err;

    size_t cmdline_len = strlen(cmdline);
    size_t payload_size = sizeof(coreid_t) + cmdline_len + 1;
    char *payload = (char *)malloc(payload_size);
    if(!payload){
        return LIB_ERR_MALLOC_FAIL;
    }

    *(coreid_t*)payload = core;
    memcpy(payload + sizeof(coreid_t), cmdline, cmdline_len +1);

    // TODO-refactor: now only static-sized bufs work at the moment!
    struct rpc_msg request = {
        .type = AosRpcSpawnRequest,
        .payload = payload,
        .bytes = payload_size,
        .cap = NULL_CAP
    };

    struct rpc_msg response;

    err = rpc_call(rpc, request, &response, false);

    domainid_t assigned_pid = *((domainid_t *)response.payload);
    DEBUG_PRINTF("spawned process with PID 0x%lx\n", assigned_pid);
    *newpid = assigned_pid;

    free(payload);

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
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    DEBUG_PRINTF("get all pids!\n");
    // TODO (M5): implement process id discovery
    errval_t err;

    /*
    size_t payload_size = 0;

    char msg_buf[AOS_LMP_MSG_SIZE(payload_size)];

    struct aos_lmp_msg *msg;
    err = aos_lmp_create_msg_no_pagefault(&msg, AosRpcGetAllPids, payload_size, NULL, NULL_CAP, (struct aos_lmp_msg*)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }
    */
    
    struct rpc_msg request={
        .type = AosRpcGetAllPids,
        .payload = NULL,
        .bytes = 0,
        .cap = NULL_CAP
    };

    struct rpc_msg response;

    err = rpc_call(rpc, request, &response, true);


    //err = aos_rpc_call(lmp, msg, false);  // lmp->recv_msg is malloced. Need to free it

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err;
    }

    *pid_count = *((size_t *)response.payload);
    //*pids = ((domainid_t *)(lmp->recv_msg->payload + sizeof(size_t)));

    *pids = malloc(*pid_count*sizeof(domainid_t));
    memcpy(*pids, response.payload + sizeof(size_t), *pid_count*sizeof(domainid_t));

    //free(lmp->recv_msg);

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
    return get_init_rpc();
}

