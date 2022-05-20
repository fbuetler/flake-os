
#include <aos/nameserver.h>
#include <aos/aos_network.h>

#include "enet_service.h"


static errval_t
aos_network_handle_icmp_send(struct enet_driver_state *st,
                             struct aos_socket_msg_icmp_send_request icmp_send,
                             void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_icmp_socket_send(st, icmp_send.ip_remote, icmp_send.type, icmp_send.id,
                                icmp_send.seqno, icmp_send.data, icmp_send.bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send over ICMP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t aos_network_handle_icmp_recv(struct enet_driver_state *st,
                                             struct aos_socket_msg_empty icmp_recv,
                                             void **response, size_t *response_bytes)
{
    errval_t err;

    struct icmp_socket_buf *buf;
    err = enet_icmp_socket_receive(st, &buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive from ICMP socket");
        return err;
    }

    *response = (void *)buf->data;
    *response_bytes = buf->len;

    return SYS_ERR_OK;
}

static errval_t
aos_network_handle_udp_create(struct enet_driver_state *st,
                              struct aos_socket_msg_udp_create_request udp_create,
                              void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_create_udp_socket(st, udp_create.port_local);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create UDP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
aos_network_handle_udp_destroy(struct enet_driver_state *st,
                               struct aos_socket_msg_udp_destroy_request udp_destroy,
                               void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_destroy_udp_socket(st, udp_destroy.port_local);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to destroy UDP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t aos_network_handle_udp_send(struct enet_driver_state *st,
                                            struct aos_socket_msg_udp_send_request udp_send,
                                            void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_udp_socket_send(st, udp_send.port_local, udp_send.ip_remote,
                               udp_send.port_remote, udp_send.data, udp_send.bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send over UDP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t aos_network_handle_udp_recv(struct enet_driver_state *st,
                                            struct aos_socket_msg_udp_recv_request udp_recv,
                                            void **response, size_t *response_bytes)
{
    errval_t err;

    struct udp_socket_buf *buf;
    err = enet_udp_socket_receive(st, udp_recv.port_local, &buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive from UDP socket");
        return err;
    }

    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg) + buf->len);
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->type = AOS_NETWORK_RESPONSE;
    msg->payload.udp_recv_resp = (struct aos_socket_msg_udp_recv_response) {
        .ip_remote = buf->ip,
        .port_remote = buf->port,
        .bytes = buf->len,
    };
    memcpy(msg->payload.udp_recv_resp.data, buf->data, buf->len);

    *response = msg;
    *response_bytes = sizeof(*msg);

    return SYS_ERR_OK;
}

static void enet_recv_handle(void *st_raw, void *message_raw, size_t bytes,
                             void **response, size_t *response_bytes,
                             struct capref rx_cap, struct capref *tx_cap)
{
    errval_t err;

    struct enet_driver_state *st = (struct enet_driver_state *)st_raw;
    struct aos_socket_msg *msg = (struct aos_socket_msg *)message_raw;

    switch (msg->type) {
    case AOS_NETWORK_ICMP_SEND_REQUEST:
        err = aos_network_handle_icmp_send(st, msg->payload.icmp_send_req, response,
                                           response_bytes);
        break;
    case AOS_NETWORK_ICMP_RECV_REQUEST:
        err = aos_network_handle_icmp_recv(st, msg->payload.icmp_recv_req, response,
                                           response_bytes);
        break;
    case AOS_NETWORK_UDP_CREATE_REQUEST:
        err = aos_network_handle_udp_create(st, msg->payload.udp_create_req, response,
                                            response_bytes);
        break;
    case AOS_NETWORK_UDP_DESTROY_REQUEST:
        err = aos_network_handle_udp_destroy(st, msg->payload.udp_destroy_req, response,
                                             response_bytes);
        break;
    case AOS_NETWORK_UDP_SEND_REQUEST:
        err = aos_network_handle_udp_send(st, msg->payload.udp_send_req, response,
                                          response_bytes);
        break;
    case AOS_NETWORK_UDP_RECV_REQUEST:
        err = aos_network_handle_udp_recv(st, msg->payload.udp_recv_req, response,
                                          response_bytes);
        break;
    default:
        err = LIB_ERR_SHOULD_NOT_GET_HERE;
        break;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to handle network message");
    }
}

errval_t enet_service_init(struct enet_driver_state *st)
{
    errval_t err;

    DEBUG_PRINTF("register with nameservice '%s'\n", ENET_SERVICE_NAME);
    err = nameservice_register(ENET_SERVICE_NAME, enet_recv_handle, st);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to register service receive handler");
        return err;
    }

    return SYS_ERR_OK;
}