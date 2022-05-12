/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */
#ifndef ENET_SOCKET_H_
#define ENET_SOCKET_H_ 1

#include <aos/aos.h>

#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/icmp.h>
#include <netutil/udp.h>

#include "enet_safe_queue.h"

// forward declaration
struct enet_driver_state;

enum socket_proto {
    ENET_SOCKET_UDP,
};

struct socket_buf {
    ip_addr_t ip;
    uint16_t port;
    char *data;
    size_t len;
    struct socket_buf *next;
};

struct socket {
    enum socket_proto proto;

    // UDP
    uint16_t port;
    struct socket_buf *inbound_head;  // consume
    struct socket_buf *inbound_tail;  // produce

    struct socket *next;
};

errval_t enet_create_socket(struct enet_driver_state *st, enum socket_proto proto,
                            uint16_t port);
errval_t enet_destroy_socket(struct enet_driver_state *st, uint16_t port);

errval_t enet_socket_handle_inbound(struct enet_driver_state *st, ip_addr_t ip,
                                    uint16_t port, uint16_t dest_port, char *payload,
                                    size_t payload_size);

errval_t enet_socket_receive(struct socket *s, struct socket_buf **retbuf);
errval_t enet_socket_send(struct enet_driver_state *st, ip_addr_t ip_dest,
                          uint16_t port_dest, char *payload, size_t payload_size);


#endif /* ENET_SOCKET_H_ */