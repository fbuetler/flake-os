
#include <aos/nameserver.h>
#include <aos/aos_network.h>

#include "enet_service.h"

static errval_t
enet_service_handle_icmp_create(struct enet_driver_state *st,
                                struct aos_socket_msg_icmp_create_request *icmp_create,
                                void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_create_icmp_socket(st, icmp_create->pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create ICMP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_icmp_destroy(struct enet_driver_state *st,
                                 struct aos_socket_msg_icmp_destroy_request *icmp_destroy,
                                 void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_destroy_icmp_socket(st, icmp_destroy->pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to destroy ICMP socket");
        return err;
    }

    *response = NULL, *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_icmp_send(struct enet_driver_state *st,
                              struct aos_socket_msg_icmp_send_request *icmp_send,
                              void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_icmp_socket_send(st, icmp_send->ip_remote, icmp_send->type, icmp_send->id,
                                icmp_send->seqno, icmp_send->data, icmp_send->bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send over ICMP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_icmp_recv(struct enet_driver_state *st,
                              struct aos_socket_msg_icmp_recv_request *icmp_recv,
                              void **response, size_t *response_bytes)
{
    errval_t err;

    struct icmp_socket_buf *buf;
    err = enet_icmp_socket_receive(st, icmp_recv->pid, &buf);
    if (err != ENET_ERR_SOCKET_EMPTY && err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive from ICMP socket");
        return err;
    }

    int buflen;
    if (!buf) {
        buflen = 0;
    } else {
        buflen = buf->len;
    }

    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg) + buflen);
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }

    msg->type = AOS_NETWORK_RESPONSE;
    msg->payload.icmp_recv_resp = (struct aos_socket_msg_icmp_recv_response) {
        .bytes = buflen,
    };

    if (buflen > 0) {
        msg->payload.icmp_recv_resp.ip_remote = buf->ip;
        msg->payload.icmp_recv_resp.type = buf->type;
        msg->payload.icmp_recv_resp.id = buf->id;
        msg->payload.icmp_recv_resp.seqno = buf->seqno;
        memcpy(msg + 1, buf->data, buflen);
    }

    *response = msg;
    *response_bytes = sizeof(struct aos_socket_msg) + buflen;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_udp_create(struct enet_driver_state *st,
                               struct aos_socket_msg_udp_create_request *udp_create,
                               void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_create_udp_socket(st, udp_create->port_local);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create UDP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_udp_destroy(struct enet_driver_state *st,
                                struct aos_socket_msg_udp_destroy_request *udp_destroy,
                                void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_destroy_udp_socket(st, udp_destroy->port_local);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to destroy UDP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_udp_send(struct enet_driver_state *st,
                             struct aos_socket_msg_udp_send_request *udp_send,
                             void **response, size_t *response_bytes)
{
    errval_t err;

    err = enet_udp_socket_send(st, udp_send->port_local, udp_send->ip_remote,
                               udp_send->port_remote, (char *)(udp_send + 1),
                               udp_send->bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send over UDP socket");
        return err;
    }

    *response = NULL;
    *response_bytes = 0;

    return SYS_ERR_OK;
}

static errval_t
enet_service_handle_udp_recv(struct enet_driver_state *st,
                             struct aos_socket_msg_udp_recv_request *udp_recv,
                             void **response, size_t *response_bytes)
{
    errval_t err;

    struct udp_socket_buf *buf = NULL;
    err = enet_udp_socket_receive(st, udp_recv->port_local, &buf);
    if (err != ENET_ERR_SOCKET_EMPTY && err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive from UDP socket");
        return err;
    }

    int buflen;
    if (!buf) {
        buflen = 0;
    } else {
        buflen = buf->len;
    }

    struct aos_socket_msg *msg = (struct aos_socket_msg *)malloc(
        sizeof(struct aos_socket_msg) + buflen);
    if (!msg) {
        return LIB_ERR_MALLOC_FAIL;
    }

    msg->type = AOS_NETWORK_RESPONSE;
    msg->payload.udp_recv_resp = (struct aos_socket_msg_udp_recv_response) {
        .bytes = buflen,
    };

    if (buflen > 0) {
        msg->payload.udp_recv_resp.ip_remote = buf->ip;
        msg->payload.udp_recv_resp.port_remote = buf->port;
        memcpy(msg + 1, buf->data, buflen);
    }

    *response = msg;
    *response_bytes = sizeof(struct aos_socket_msg) + buflen;

    return SYS_ERR_OK;
}

static void enet_recv_handle(void *st_raw, void *message_raw, size_t bytes,
                             void **response, size_t *response_bytes,
                             struct capref rx_cap, struct capref *tx_cap)
{
    errval_t err;

    struct enet_driver_state *st = (struct enet_driver_state *)st_raw;
    struct aos_socket_msg *msg = (struct aos_socket_msg *)message_raw;

    ENET_BENCHMARK_INIT()
    switch (msg->type) {
    case AOS_NETWORK_ICMP_CREATE_REQUEST:
        ENET_BENCHMARK_START(0, "icmp create service")
        err = enet_service_handle_icmp_create(st, &msg->payload.icmp_create_req, response,
                                              response_bytes);
        ENET_BENCHMARK_STOP(0, "icmp create service")
        break;
    case AOS_NETWORK_ICMP_DESTROY_REQUEST:
        ENET_BENCHMARK_START(0, "icmp destroy service")
        err = enet_service_handle_icmp_destroy(st, &msg->payload.icmp_destroy_req,
                                               response, response_bytes);
        ENET_BENCHMARK_STOP(0, "icmp destroy service")
        break;
    case AOS_NETWORK_ICMP_SEND_REQUEST:
        ENET_BENCHMARK_START(0, "icmp send service")
        err = enet_service_handle_icmp_send(st, &msg->payload.icmp_send_req, response,
                                            response_bytes);
        ENET_BENCHMARK_STOP(0, "icmp send service")
        break;
    case AOS_NETWORK_ICMP_RECV_REQUEST:
        ENET_BENCHMARK_START(0, "icmp receive service")
        err = enet_service_handle_icmp_recv(st, &msg->payload.icmp_recv_req, response,
                                            response_bytes);
        ENET_BENCHMARK_STOP(0, "icmp receive service")
        break;
    case AOS_NETWORK_UDP_CREATE_REQUEST:
        ENET_BENCHMARK_START(0, "udp create service")
        err = enet_service_handle_udp_create(st, &msg->payload.udp_create_req, response,
                                             response_bytes);
        ENET_BENCHMARK_STOP(0, "udp create service")
        break;
    case AOS_NETWORK_UDP_DESTROY_REQUEST:
        ENET_BENCHMARK_START(0, "udp destroy service")
        err = enet_service_handle_udp_destroy(st, &msg->payload.udp_destroy_req, response,
                                              response_bytes);
        ENET_BENCHMARK_STOP(0, "udp destroy service")
        break;
    case AOS_NETWORK_UDP_SEND_REQUEST:
        ENET_BENCHMARK_START(0, "udp send service")
        err = enet_service_handle_udp_send(st, &msg->payload.udp_send_req, response,
                                           response_bytes);
        ENET_BENCHMARK_STOP(0, "udp send service")
        break;
    case AOS_NETWORK_UDP_RECV_REQUEST:
        ENET_BENCHMARK_START(0, "udp receive service")
        err = enet_service_handle_udp_recv(st, &msg->payload.udp_recv_req, response,
                                           response_bytes);
        ENET_BENCHMARK_STOP(0, "udp receive service")
        break;
    default:
        err = LIB_ERR_SHOULD_NOT_GET_HERE;
        break;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to handle network message");
        *response = NULL;
        *response_bytes = 0;
    }
}

errval_t enet_service_init(struct enet_driver_state *st)
{
    errval_t err;

    DEBUG_PRINTF("Registering with nameservice '%s'\n", ENET_SERVICE_NAME);
    err = nameservice_register(ENET_SERVICE_NAME, enet_recv_handle, st);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to register service receive handler");
        return err;
    }
    DEBUG_PRINTF("Registered with nameservice '%s'\n", ENET_SERVICE_NAME);

    return SYS_ERR_OK;
}