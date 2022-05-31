/**
 * \file nameservice.h
 * \brief
 */
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/nameserver.h>
#include <aos/aos_rpc.h>


#include <hashtable/hashtable.h>

///< a valid name is composed from parts of snake case strings, where every part is at
///< least two characters long, starts with a letter and does not end with an underscore.
///< The name parts are separated by a dot.
static const char *name_pattern = "^[a-z][a-z0-9_]*[a-z0-9](\\.[a-z][a-z0-9_]*[a-z0-9])*"
                                  "$";

bool name_is_valid(char *name)
{
    if (name == NULL) {
        return false;
    }

    regex_t regex;
    if (regcomp(&regex, name_pattern, REG_EXTENDED | REG_NOSUB)) {
        USER_PANIC("Failed to compile regex to validate names\n");
    }

    int regex_res = regexec(&regex, name, 0, NULL, 0);

    return regex_res == 0;
}

errval_t name_into_parts(char *name, struct name_parts *ret)
{
    if (!name_is_valid(name)) {
        // DEBUG_PRINTF("\"%s\" is an invalid name\n", name);
        return LIB_ERR_NAMESERVICE_INVALID_NAME;
    }

    size_t full_len = strlen(name) + 1;  // incl NULL byte
    size_t num_parts = 1;
    for (char *c = name; *c != '\0'; c++) {
        if (*c == '.') {
            num_parts++;
        }
    }

    char **parts = malloc(sizeof(char *[num_parts]));
    if (parts == NULL) {
        DEBUG_PRINTF("Failed to allocate array for name parts\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    // copy the entire name into a new buffer
    char *name_buf = malloc(full_len);
    if (name_buf == NULL) {
        free(parts);
        DEBUG_PRINTF("Failed to allocate buffer to store the name\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    name_buf = strncpy(name_buf, name, full_len);

    // replace every separator ('.') with a NULL byte and point beginning of the next part
    // to the next byte
    parts[0] = name_buf;
    size_t part = 1;
    for (char *c = name_buf; *c != '\0'; c++) {
        if (*c == '.') {
            *c = '\0';
            parts[part] = c + 1;
            part++;
        }
    }

    ret->num_parts = num_parts;
    ret->parts = parts;

    return SYS_ERR_OK;
}

void name_parts_contents_free(struct name_parts *p)
{
    free(p->parts[0]);
    free(p->parts);
}


errval_t service_info_new(coreid_t core, nameservice_receive_handler_t *handle,
                          void *handler_state, domainid_t pid, const char *name,
                          service_info_t **ret)
{
    size_t name_len = strlen(name) + 1;
    *ret = malloc(sizeof(service_info_t) + name_len);
    if (*ret == NULL) {
        DEBUG_PRINTF("Failed to allocate service info\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    (*ret)->core = core;
    (*ret)->handle = handle;
    (*ret)->handler_state = handler_state;
    (*ret)->pid = pid;
    (*ret)->name_len = name_len;
    memcpy((*ret)->name, name, name_len);

    return SYS_ERR_OK;
}

size_t service_info_size(service_info_t *info)
{
    return sizeof(service_info_t) + info->name_len;
}

struct srv_entry {
    const char *name;
    nameservice_receive_handler_t *recv_handler;
    void *st;
};

struct nameservice_chan {
    struct aos_rpc rpc;
    char *name;
};


/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @param message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_bytes the size of the response
 *
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes,
                         void **response, size_t *response_bytes, struct capref tx_cap,
                         struct capref *rx_cap)
{
    errval_t err;

    struct nameservice_rpc_msg *nsrpcmsg = malloc(sizeof(struct nameservice_rpc_msg)
                                                  + bytes);
    if (nsrpcmsg == NULL) {
        DEBUG_PRINTF("Failed to allocate nameservice message\n");
        return LIB_ERR_MALLOC_FAIL;
    }
    nsrpcmsg->handler = chan->handler;
    nsrpcmsg->st = chan->st;
    nsrpcmsg->bytes = bytes;
    memcpy(nsrpcmsg->message, message, bytes);
    // DEBUG_PRINTF("ptr: %p, bytes: %zu\n", nsrpcmsg, bytes);

    struct aos_rpc_msg msg = { .type = AosRpcClientRequest,
                               .payload = (char *)nsrpcmsg,
                               .bytes = sizeof(struct nameservice_rpc_msg) + bytes,
                               .cap = tx_cap };

    struct aos_rpc_msg ret_msg;
    err = aos_rpc_call(&chan->rpc, msg, &ret_msg);
    free(nsrpcmsg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to execute nameservice RPC call");
        return err_push(err, LIB_ERR_RPC_CALL);
    }

    *response = (void *)ret_msg.payload;
    if (response_bytes)
        *response_bytes = ret_msg.bytes;
    if (rx_cap) {
        *rx_cap = ret_msg.cap;
    }

    return SYS_ERR_OK;
}


/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name,
                              nameservice_receive_handler_t recv_handler, void *st)
{
    errval_t err;

    service_info_t *info;
    err = service_info_new(disp_get_current_core_id(), recv_handler, st,
                           disp_get_domain_id(), name, &info);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to create new service info");
        return err_push(err, LIB_ERR_NAMESERVICE_NEW_INFO);
    }

    // DEBUG_PRINTF("Registering new service %s with PID %d\n", name, info->pid);

    struct aos_rpc_msg msg = { .type = AosRpcNsRegister,
                               .payload = (char *)info,
                               sizeof(service_info_t) + info->name_len,
                               NULL_CAP };

    struct aos_rpc *init_rpc = get_init_rpc();
    struct aos_rpc_msg response;
    err = aos_rpc_call(init_rpc, msg, &response);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to execute rpc call to register service");
        return err_push(err, LIB_ERR_RPC_CALL);
    }

    assert(response.type == AosRpcErrvalResponse);
    err = *(errval_t *)response.payload;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failure registering the service at the nameserver");
        return err;
    }

    return SYS_ERR_OK;
}


/**
 * @brief deregisters the service 'name'
 *
 * @param name the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *nschan)
{
    errval_t err = SYS_ERR_OK;

    size_t name_len = strlen(name) + 1;
    char *name_copy = malloc(name_len);
    name_copy = strncpy(name_copy, name, name_len);
    assert(name_copy[name_len -1] == '\0');

    struct aos_rpc_msg request = { .type = AosRpcNsLookup,
                                   .payload = name_copy,
                                   .bytes = name_len,
                                   .cap = NULL_CAP };

    struct aos_rpc *init_rpc = get_init_rpc();
    struct aos_rpc_msg response;

    // DEBUG_PRINTF("Looking up service at the nameserver\n");
    err = aos_rpc_call(init_rpc, request, &response);
    free(name_copy);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to execute rpc call to lookup service");
        return err_push(err, LIB_ERR_RPC_CALL);
    }

    if (response.type == AosRpcErrvalResponse) {
        err = *(errval_t *)response.payload;
        //DEBUG_ERR(err, "Failure looking up service at nameservice");
        return err;
    } else if (response.type != AosRpcNsLookupResponse) {
        DEBUG_PRINTF("Expected message of type AosRpcNsLookupResponse or "
                     "AosRpcErrvalResponse\n");
        return LIB_ERR_RPC_UNEXPECTED_MSG_TYPE;
    }

    // freeing info will also free the response payload
    service_info_t *info = (service_info_t *)response.payload;

    // Set up the channel that is to be returned
    *nschan = malloc(sizeof(struct aos_rpc) + 2 * sizeof(void *));
    if (*nschan == NULL) {
        DEBUG_PRINTF("Failed to allocate new nameservice channel\n");
        err = LIB_ERR_MALLOC_FAIL;
        goto free_si;
    }
    (*nschan)->handler = info->handle;
    (*nschan)->st = info->handler_state;

    // Set up the RPC channel that will be bound to the server
    // DEBUG_PRINTF("Setting up RPC channel to server with PID %d\n", info->pid);
    struct aos_rpc *new_rpc = &(*nschan)->rpc;

    if (info->core == disp_get_current_core_id()) {
        // DEBUG_PRINTF("Setting up LMP channel\n");
        //  We can use an LMP channel
        new_rpc->is_lmp = true;

        // DEBUG_PRINTF("Initializing LMP channel\n");
        err = aos_lmp_init(&new_rpc->u.lmp, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to initialize LMP channel to server");
            err = err_push(err, LIB_ERR_LMP_INIT);
            goto free_nschan;
        }

        // setup CNode slot to receive remote cap from server
        err = lmp_chan_alloc_recv_slot(&new_rpc->u.lmp.chan);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to allocate recieve slot for server cap");
            err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
            goto free_nschan;
        }

        // DEBUG_PRINTF("Starting LMP bind request\n");
        struct aos_rpc_msg bind_req = { .type = AosRpcLmpBind,
                                        .cap = new_rpc->u.lmp.chan.local_cap,
                                        .payload = (char *)&info->pid,
                                        .bytes = sizeof(domainid_t) };

        struct aos_rpc_msg bind_resp;
        err = aos_rpc_call(init_rpc, bind_req, &bind_resp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to send LMP bind request to init");
            err = err_push(err, LIB_ERR_BIND_LMP_REQ);
            goto free_nschan;
        }
        // DEBUG_PRINTF("Successfully performed LMP bind request\n");

        if (bind_resp.type != AosRpcErrvalResponse) {
            free(bind_resp.payload);
            DEBUG_PRINTF("Expected message of type AosRpcErrvalResponse\n");
            err = LIB_ERR_RPC_UNEXPECTED_MSG_TYPE;
            goto free_nschan;
        }

        err = *(errval_t *)bind_resp.payload;
        free(bind_resp.payload);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to execute LMP bind request in init");
            err = err_push(err, LIB_ERR_BIND_LMP_REQ);
            goto free_nschan;
        }

        err = aos_lmp_init_handshake_to_child(&new_rpc->u.lmp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to perform handshake with server");
            err = err_push(err, LIB_ERR_LMP_INIT_CAPTRANSFER);
            goto free_nschan;
        }

    } else {
        // We need to use an UMP channel to the other core
        new_rpc->is_lmp = false;
        return LIB_ERR_NOT_IMPLEMENTED;
    }

free_si:
    free(info);
    return err;

// The channel needs to be returned if the function does not fail. Therefore, it is behind
// the return so it is not freed in the good case
free_nschan:
    free(nschan);
    goto free_si;
}


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char **result)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}
