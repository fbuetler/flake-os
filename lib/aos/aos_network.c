#include <aos/nameserver.h>

#include <aos/aos_network.h>

errval_t aos_udp_socket_create(uint16_t port, struct aos_udp_socket **socket)
{
    errval_t err;

    // setup channel
    nameservice_chan_t chan;
    err = nameservice_lookup(ENET_SERVICE_NAME, &chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to lookup service");
        return err;
    }

    // setup request
    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg));
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->type = AOS_NETWORK_UDP_SEND_REQUEST;
    msg->payload.udp_create_req = (struct aos_socket_msg_udp_create_request) {
        .port_local = port,
    };

    void *request = msg;
    size_t request_bytes = sizeof(*msg);

    // get response
    void *response;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_bytes, &response, &response_bytes,
                          NULL_CAP, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message to network service");
        return err;
    }

    *socket = (struct aos_udp_socket *)malloc(sizeof(struct aos_udp_socket));
    if (!socket) {
        return LIB_ERR_MALLOC_FAIL;
    }
    (*socket)->port = port;

    // free(udp_create);
    // free(msg);

    return SYS_ERR_OK;
}

errval_t aos_udp_socket_release(struct aos_udp_socket *socket)
{
    errval_t err;

    // setup channel
    nameservice_chan_t chan;
    err = nameservice_lookup(ENET_SERVICE_NAME, &chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to lookup service");
        return err;
    }

    // setup request
    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg));
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->type = AOS_NETWORK_UDP_DESTROY_REQUEST;
    msg->payload.udp_destroy_req = (struct aos_socket_msg_udp_destroy_request) {
        .port_local = socket->port,
    };

    void *request = msg;
    size_t request_bytes = sizeof(*msg);

    // get response
    void *response;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_bytes, &response, &response_bytes,
                          NULL_CAP, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message to network service");
        return err;
    }

    // free(msg);

    return SYS_ERR_OK;
}

errval_t aos_udp_socket_send(struct aos_udp_socket *socket, ip_addr_t ip, uint16_t port,
                             char *message, size_t message_size)
{
    errval_t err;

    // setup channel
    nameservice_chan_t chan;
    err = nameservice_lookup(ENET_SERVICE_NAME, &chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to lookup service");
        return err;
    }

    // setup request
    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg) + message_size);
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->type = AOS_NETWORK_UDP_SEND_REQUEST;
    msg->payload.udp_send_req = (struct aos_socket_msg_udp_send_request) {
        .port_local = socket->port,
        .ip_remote = ip,
        .port_remote = port,
        .bytes = message_size,
    };
    memcpy(msg->payload.udp_send_req.data, message, message_size);

    void *request = msg;
    size_t request_bytes = sizeof(*msg);

    // get response
    void *response;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_bytes, &response, &response_bytes,
                          NULL_CAP, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message to network service");
        return err;
    }

    // free(payload);
    // free(udp_send);
    // free(msg);

    return SYS_ERR_OK;
}

errval_t aos_udp_socket_recv(struct aos_udp_socket *socket, ip_addr_t *ip, uint16_t *port,
                             char **message, size_t *message_size)
{
    errval_t err;

    // setup channel
    nameservice_chan_t chan;
    err = nameservice_lookup(ENET_SERVICE_NAME, &chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to lookup service");
        return err;
    }


    // setup request
    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg));
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->type = AOS_NETWORK_UDP_RECV_REQUEST;
    msg->payload.udp_recv_req = (struct aos_socket_msg_udp_recv_request) {
        .port_local = socket->port,
    };

    void *request = msg;
    size_t request_bytes = sizeof(*msg);

    // get response
    void *response;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_bytes, &response, &response_bytes,
                          NULL_CAP, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message to network service");
        return err;
    }

    struct aos_socket_msg *msg_resp = (struct aos_socket_msg *)response;
    struct aos_socket_msg_udp_recv_response payload = msg_resp->payload.udp_recv_resp;

    *ip = payload.ip_remote;
    *port = payload.port_remote;
    *message = (char *)malloc(payload.bytes);
    if (!*message) {
        return LIB_ERR_MALLOC_FAIL;
    }
    memcpy(*message, payload.data, payload.bytes);
    *message_size = payload.bytes;

    // free(msg);

    return SYS_ERR_OK;
}
