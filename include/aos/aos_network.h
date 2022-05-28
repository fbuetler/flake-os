#ifndef _INIT_AOS_NETWORK_H
#define _INIT_AOS_NETWORK_H

#include <aos/aos.h>
#include <netutil/ip.h>

#define ENET_SERVICE_NAME "enet_service"

#define AOS_NETWORK_DEBUG_OPTION 1

#if defined(AOS_NETWORK_DEBUG_OPTION)
#    define AOS_NETWORK_DEBUG(x...) debug_printf("[network] " x);
#else
#    define AOS_NETWORK_DEBUG(fmt, ...) ((void)0)
#endif

struct aos_udp_socket {
    uint16_t port;
};

struct aos_icmp_socket {
};

// used to communicate with the network service handler
enum aos_network_msg_type {
    AOS_NETWORK_ICMP_SEND_REQUEST = 1,
    AOS_NETWORK_ICMP_RECV_REQUEST = 2,
    AOS_NETWORK_UDP_CREATE_REQUEST = 3,
    AOS_NETWORK_UDP_DESTROY_REQUEST = 4,
    AOS_NETWORK_UDP_SEND_REQUEST = 5,
    AOS_NETWORK_UDP_RECV_REQUEST = 6,
    AOS_NETWORK_RESPONSE
    = 100,  // calls are synchronous, so we already now the response type
};

struct aos_socket_msg_empty {
};

struct aos_socket_msg_udp_create_request {
    uint16_t port_local;
};

struct aos_socket_msg_udp_destroy_request {
    uint16_t port_local;
};

struct aos_socket_msg_udp_send_request {
    uint16_t port_local;
    ip_addr_t ip_remote;
    uint16_t port_remote;
    size_t bytes;
    char *data;
};

struct aos_socket_msg_udp_recv_request {
    uint16_t port_local;
};

struct aos_socket_msg_udp_recv_response {
    ip_addr_t ip_remote;
    uint16_t port_remote;
    size_t bytes;
    char *data;
};

struct aos_socket_msg_icmp_send_request {
    ip_addr_t ip_remote;
    uint8_t type;
    uint16_t id;
    uint16_t seqno;
    size_t bytes;
    char *data;
};

struct aos_socket_msg_icmp_recv_response {
    ip_addr_t ip_remote;
    uint8_t type;
    uint16_t id;
    uint16_t seqno;
    size_t bytes;
    char *data;
};

union aos_socket_msg_payload {
    struct aos_socket_msg_udp_create_request udp_create_req;
    struct aos_socket_msg_empty udp_create_resp;
    struct aos_socket_msg_udp_destroy_request udp_destroy_req;
    struct aos_socket_msg_empty udp_destroy_resp;
    struct aos_socket_msg_udp_send_request udp_send_req;
    struct aos_socket_msg_empty udp_send_resp;
    struct aos_socket_msg_udp_recv_request udp_recv_req;
    struct aos_socket_msg_udp_recv_response udp_recv_resp;
    struct aos_socket_msg_icmp_send_request icmp_send_req;
    struct aos_socket_msg_empty icmp_send_resp;
    struct aos_socket_msg_empty icmp_recv_req;
    struct aos_socket_msg_icmp_recv_response icmp_recv_resp;
};

struct aos_socket_msg {
    enum aos_network_msg_type type;
    union aos_socket_msg_payload payload;
};

errval_t aos_udp_socket_create(uint16_t port, struct aos_udp_socket **socket);
errval_t aos_udp_socket_release(struct aos_udp_socket *socket);
errval_t aos_udp_socket_send(struct aos_udp_socket *socket, ip_addr_t ip, uint16_t port,
                             char *message, size_t message_size);
errval_t aos_udp_socket_recv(struct aos_udp_socket *socket, ip_addr_t *ip, uint16_t *port,
                             char **message, size_t *message_size);

// TODO implement
errval_t aos_icmp_socket_create(uint16_t port, struct aos_icmp_socket **socket);
errval_t aos_icmp_socket_release(struct aos_icmp_socket *socket);
errval_t aos_icmp_socket_send(struct aos_icmp_socket *socket, ip_addr_t ip, uint8_t type,
                              uint16_t id, uint16_t seqno, char *message,
                              size_t message_size);
errval_t aos_icmp_socket_recv(struct aos_icmp_socket *socket, char **message,
                              size_t *message_size);

#endif