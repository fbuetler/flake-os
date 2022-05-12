
#include "enet_service.h"

#include <aos/aos_network.h>

static errval_t aos_network_handle_icmp_send(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_icmp_recv(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_udp_create(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_udp_destroy(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_udp_send(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_udp_recv(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_udp_send(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t aos_network_handle_udp_recv(struct enet_driver_state *st)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t enet_service_handle()
{
    errval_t err;

    // TODO
    enum aos_network_msg_type msg_type;
    struct enet_driver_state *st;

    switch (msg_type) {
    case AOS_NETWORK_ICMP_SEND:
        err = aos_network_handle_icmp_send(st);
        break;
    case AOS_NETWORK_ICMP_RECV:
        err = aos_network_handle_icmp_recv(st);
        break;
    case AOS_NETWORK_UDP_CREATE:
        err = aos_network_handle_udp_create(st);
        break;
    case AOS_NETWORK_UDP_DESTROY:
        err = aos_network_handle_udp_destroy(st);
        break;
    case AOS_NETWORK_UDP_SEND:
        err = aos_network_handle_udp_send(st);
        break;
    case AOS_NETWORK_UDP_RECV:
        err = aos_network_handle_udp_recv(st);
        break;
    default:
        err = LIB_ERR_SHOULD_NOT_GET_HERE;
        break;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to handle network message");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t enet_service_init(struct enet_driver_state *st)
{
    // TODO register enet_service_handle at nameserver
    return LIB_ERR_NOT_IMPLEMENTED;
}