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

    struct nameservice_rpc_msg nsrpcmsg
        = { .handler = chan->handler, .st = chan->st, .message = message, .bytes = bytes };
    struct aos_rpc_msg msg = { .type = AosRpcClientRequest,
                               .payload = (char *)&nsrpcmsg,
                               .bytes = sizeof(struct nameservice_rpc_msg),
                               .cap = tx_cap };

    struct aos_rpc_msg ret_msg;
    err = aos_rpc_call(&chan->rpc, msg, &ret_msg, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to execute nameservice RPC call");
        return err_push(err, LIB_ERR_RPC_CALL);
    }

    *response = (void *)ret_msg.payload;
    *response_bytes = ret_msg.bytes;
    *rx_cap = ret_msg.cap;

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

    struct aos_rpc_msg msg = { .type = AosRpcNsRegister,
                               .payload = (char *)info,
                               sizeof(service_info_t) + info->name_len,
                               NULL_CAP };

    struct aos_rpc *init_rpc = get_init_rpc();
    struct aos_rpc_msg response;
    err = aos_rpc_call(init_rpc, msg, &response, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to execute rpc call to register service");
        return err_push(err, LIB_ERR_RPC_CALL);
    }

    assert(response.type == AosRpcErrvalResponse);

    return (errval_t)*response.payload;
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
    errval_t err;

    char *name_copy = malloc(strlen(name) + 1);
    name_copy = strncpy(name_copy, name, strlen(name));

    struct aos_rpc_msg request = {
        .type = AosRpcNsLookup, .payload = name_copy, .bytes = strlen(name), .cap = NULL_CAP
    };

    struct aos_rpc *init_rpc = get_init_rpc();
    struct aos_rpc_msg response;

    DEBUG_PRINTF("Looking up service at the nameserver\n");
    err = aos_rpc_call(init_rpc, request, &response, false);
    free(name_copy);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to execute rpc call to lookup service");
        return err_push(err, LIB_ERR_RPC_CALL);
    }
    DEBUG_PRINTF("Found service\n");

    service_info_t *info = (service_info_t *)response.payload;

    *nschan = malloc(sizeof(struct aos_rpc) + 2 * sizeof(void *));
    if (*nschan == NULL) {
        DEBUG_PRINTF("Failed to allocate new nameservice channel\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    (*nschan)->handler = info->handle;
    (*nschan)->st = info->handler_state;
    struct aos_rpc *new_rpc = &(*nschan)->rpc;

    if (info->core == disp_get_current_core_id()) {
        DEBUG_PRINTF("Setting up LMP channel\n");
        // We can use an LMP channel
        new_rpc->is_lmp = true;

        struct aos_rpc_msg bind_req = { .type = AosRpcLmpBind,
                                        .cap = cap_selfep,
                                        .payload = (char *)&info->pid,
                                        .bytes = sizeof(domainid_t) };
        struct aos_rpc_msg bind_resp;
        err = aos_rpc_call(init_rpc, bind_req, &bind_resp, false);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to send LMP bind request to init");
            return err_push(err, LIB_ERR_BIND_LMP_REQ);
        }
        DEBUG_PRINTF("Performed LMP bind request\n");

        assert(bind_resp.type == AosRpcErrvalResponse);
        err = *(errval_t *)bind_resp.payload;
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to execute LMP bind request in init");
            return err_push(err, LIB_ERR_BIND_LMP_REQ);
        }

        DEBUG_PRINTF("Initializing LMP channel\n");
        struct capref server_ep = bind_resp.cap;
        err = aos_lmp_init(&new_rpc->u.lmp, server_ep);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to initialize LMP channel to server");
            return err_push(err, LIB_ERR_LMP_INIT);
        }
    } else {
        // We need to use an LMP channel to the other core
        new_rpc->is_lmp = false;
        return LIB_ERR_NOT_IMPLEMENTED;
    }


    return SYS_ERR_OK;
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
