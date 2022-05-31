/**
 * \file
 * \brief Ping application
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
#include <aos/deferred.h>
#include <netutil/icmp.h>

#define MK_IP(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static void parse_ip(char *raw_ip, int *ip)
{
    int offset = 0;
    int len = strlen(raw_ip);
    for (int i = 0; i < 4; i++) {
        char part[4];
        int part_offset = 0;
        while (offset < len && raw_ip[offset] != '.') {
            part[part_offset] = raw_ip[offset];
            part_offset++;
            offset++;
        }
        offset++;  // consume dot
        part[part_offset] = '\0';
        ip[i] = atoi(part);
    }
}

int main(int argc, char *argv[])
{
    errval_t err;

    if (argc != 4) {
        err = LIB_ERR_SHOULD_NOT_GET_HERE;
        DEBUG_ERR(err, "Invalid number of arguments. Expected: ping -c <count> <host>");
        return err;
    }

    uint16_t count = atoi(argv[2]);

    int ip_parts[4];
    parse_ip(argv[3], ip_parts);
    ip_addr_t ip = MK_IP(ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]);

    domainid_t pid = disp_get_domain_id();

    // create socket
    // debug_printf("Creating socket\n");
    struct aos_icmp_socket *sock;
    err = aos_icmp_socket_create(pid, &sock);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create socket");
        return err;
    }

    char *payload = "SUPERAWESOMEPINGPAYLOAD";
    debug_printf("PING %d.%d.%d.%d with %d bytes of data.\n", ip_parts[0], ip_parts[1],
                 ip_parts[2], ip_parts[3], strlen(payload));
    // init stats keeper
    for (int i = 0; i < count; i++) {
        // send icmp echo
        // debug_printf("Send ping %d\n", i);

        size_t retries = 0;
        size_t max_retries = 128;
        do {
            err = aos_icmp_socket_send(sock, ip, ICMP_ECHO, (uint16_t)pid, i, payload,
                                       strlen(payload));
            retries++;
            thread_yield();
            barrelfish_usleep(10 * 1000);
        } while (err == ENET_ERR_ARP_RESOLUTION && retries < max_retries);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to send ICMP echo %d", i);
            continue;
        }

        // start timer for seqno
        systime_t start = get_system_time();

        // receive icmp echo reply
        uint8_t type;
        uint16_t id;
        uint16_t seqno;
        char *msg;
        size_t msg_size;
        do {
            debug_printf("wait for echo reply icmp_seq=%d\n", i);
            err = aos_icmp_socket_recv(sock, &type, &id, &seqno, &msg, &msg_size);
            if (err_is_fail(err)) {
                if (err != LIB_ERR_RPC_SEND) {
                    DEBUG_ERR(err, "failed to receive ICMP echo reply");
                }
                thread_yield();
                continue;
            }
            // debug_printf("Received ping type: %d id: %d\n", type, id);
        } while (type != ICMP_ER || id != pid);

        // check if icmp message payload is the same
        if (strcmp(payload, msg)) {
            DEBUG_PRINTF("mismatch in payload\n");
        }

        // stop timer for seqno
        systime_t stop = get_system_time();

        debug_printf("from %d.%d.%d.%d: icmp_seq=%d time=%d ticks\n", ip_parts[0],
                     ip_parts[1], ip_parts[2], ip_parts[3], seqno, stop - start);
    }

    // destroy socket
    debug_printf("Destroying socket\n");
    err = aos_icmp_socket_release(sock);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to destroy socket");
        return err;
    }

    return EXIT_SUCCESS;
}
