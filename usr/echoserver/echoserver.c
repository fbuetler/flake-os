/**
 * \file
 * \brief Echo server application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_network.h>

int main(int argc, char *argv[])
{
    errval_t err;

    if (argc != 3) {
        err = LIB_ERR_SHOULD_NOT_GET_HERE;
        DEBUG_ERR(err, "Invalid number of arguments. Expected: echoserver -p <port>");
        return err;
    }

    // uint16_t listening_port = atoi(argv[2]);
    uint16_t listening_port = 8000 + disp_get_domain_id();

    // start server on port
    debug_printf("Creating socket\n");
    struct aos_udp_socket *sock;
    err = aos_udp_socket_create(listening_port, &sock);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create socket");
        return err;
    }

    debug_printf("Echo server is listening on port %d...\n", listening_port);
    while (1) {
        // listen for messages
        char *msg;
        size_t size;
        ip_addr_t ip;
        uint16_t port;
        err = aos_udp_socket_recv(sock, &ip, &port, &msg, &size);
        if (err_is_fail(err)) {
            if (err != LIB_ERR_RPC_SEND) {
                DEBUG_ERR(err, "failed to receive message");
            }
            continue;
        }

        if (strlen(msg) == 0) {
            continue;
        }
        DEBUG_PRINTF("got messages: '%s'\n", msg);

        // echo them back
        err = aos_udp_socket_send(sock, ip, port, msg, size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to echo message");
            continue;
        }
    }

    return EXIT_SUCCESS;
}
