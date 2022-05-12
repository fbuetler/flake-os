#ifndef _INIT_AOS_NETWORK_H
#define _INIT_AOS_NETWORK_H

#include <aos/aos.h>

enum aos_network_msg_type {
    AOS_NETWORK_ICMP_SEND = 1,
    AOS_NETWORK_ICMP_RECV = 2,
    AOS_NETWORK_UDP_CREATE = 3,
    AOS_NETWORK_UDP_DESTROY = 4,
    AOS_NETWORK_UDP_SEND = 5,
    AOS_NETWORK_UDP_RECV = 6,
};

enum aos_socket_type {
    AOS_SOCKET_TYPE_ICMP = 1,
    AOS_SOCKET_TYPE_UDP = 2,
};

struct aos_socket {
    enum aos_socket_type type;
    union {
        struct {
            uint16_t port;
        } udp;
        struct {
        } icmp;
    } proto;
};

struct aos_socket_options {
    enum aos_socket_type type;
    union {
        struct {
            uint16_t port;
        } udp;
        struct {
        } icmp;
    } proto;
}

struct aos_socket_msg {
    char *payload;
    size_t payload_size;
};

errval_t aos_socket_create(struct aos_socket_options *opts, struct aos_socket **socket);
errval_t aos_socket_release(struct aos_socket *socket);
errval_t aos_socket_recv(struct aos_socket *socket, struct aos_socket_msg *msg);
errval_t aos_socket_send(struct aos_socket *socket, struct aos_socket_msg *msg);

#endif