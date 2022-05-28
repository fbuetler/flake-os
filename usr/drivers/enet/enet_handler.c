#include <aos/aos.h>

#include <netutil/htons.h>
#include <netutil/checksum.h>

#include "enet.h"
#include "enet_safe_queue.h"
#include "enet_debug.h"
#include "enet_assembler.h"

struct eth_addr enet_split_mac(uint64_t mac)
{
    return (struct eth_addr) { .addr = { ((mac >> 40) & 0xFF), ((mac >> 32) & 0xFF),
                                         ((mac >> 24) & 0xFF), ((mac >> 16) & 0xFF),
                                         ((mac >> 8) & 0xFF), ((mac >> 0) & 0xFF) } };
}

uint64_t enet_fuse_mac(struct eth_addr mac)
{
    return ((uint64_t)mac.addr[0] << 40) | ((uint64_t)mac.addr[1] << 32)
           | ((uint64_t)mac.addr[2] << 24) | ((uint64_t)mac.addr[3] << 16)
           | ((uint64_t)mac.addr[4] << 8) | ((uint64_t)mac.addr[5] << 0);
}

errval_t enet_get_mac_by_ip(struct enet_driver_state *st, ip_addr_t ip_dest,
                            struct eth_addr *retmac)
{
    errval_t err;

    // get from cache if available
    enet_debug_print_ip(ip_dest);
    enet_debug_print_arp_table(st->arp_table);
    uint64_t *mac = (uint64_t *)collections_hash_find(st->arp_table, ip_dest);
    if (mac) {
        *retmac = enet_split_mac(*mac);
        return SYS_ERR_OK;
    }

    // otherwise broadcast request
    struct eth_hdr *arp;
    size_t arp_size;
    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(2, "assemble arp packet")
    err = enet_assemble_arp_packet(enet_split_mac(st->mac), ENET_STATIC_IP,
                                   enet_split_mac(ETH_BROADCAST), ip_dest, ARP_OP_REQ,
                                   &arp, &arp_size);
    ENET_BENCHMARK_STOP(2, "assemble arp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble arp packet");
        return err;
    }

    ENET_BENCHMARK_START(2, "enqueue arp packet")
    err = safe_enqueue(st->safe_txq, (void *)arp, arp_size);
    ENET_BENCHMARK_STOP(2, "enqueue arp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to enqueue buffer");
        return err;
    }

    // wait until response is here
    size_t retries = 0;
    size_t max_retries = 512;
    while (retries < max_retries) {
        enet_debug_print_arp_table(st->arp_table);
        mac = (uint64_t *)collections_hash_find(st->arp_table, ip_dest);
        if (mac) {
            *retmac = enet_split_mac(*mac);
            return SYS_ERR_OK;
        }
        retries++;
        barrelfish_usleep(10 * 1000);
    }

    return ENET_ERR_ARP_RESOLUTION;
}

static errval_t enet_update_arp_table(struct enet_driver_state *st, ip_addr_t ip,
                                      struct eth_addr eth)
{
    uint64_t *eth_src = (uint64_t *)malloc(sizeof(uint64_t));
    *eth_src = enet_fuse_mac(eth);
    if (collections_hash_find(st->arp_table, ip)) {
        collections_hash_delete(st->arp_table, ip);
        collections_hash_insert(st->arp_table, ip, eth_src);
    } else {
        collections_hash_insert(st->arp_table, ip, eth_src);
    }

    enet_debug_print_arp_table(st->arp_table);

    return SYS_ERR_OK;
}

static errval_t enet_handle_arp_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct arp_hdr *arp = (struct arp_hdr *)((char *)eth + ETH_HLEN);

    enet_debug_print_arp_packet(arp);

    switch (ntohs(arp->opcode)) {
    case ARP_OP_REQ:
        // ignore requests that are not for us
        if (ntohl(arp->ip_dst) != ENET_STATIC_IP) {
            break;
        }

        // answer requests that are for us
        struct eth_hdr *resp_arp;
        size_t resp_arp_size;
        ENET_BENCHMARK_INIT()
        ENET_BENCHMARK_START(2, "assemble arp packet")
        err = enet_assemble_arp_packet(enet_split_mac(st->mac), ENET_STATIC_IP,
                                       arp->eth_src, ntohl(arp->ip_src), ARP_OP_REP,
                                       &resp_arp, &resp_arp_size);
        ENET_BENCHMARK_STOP(2, "assemble arp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to assemble arp packet");
            return err;
        }

        ENET_BENCHMARK_START(2, "enqueue arp packet")
        err = safe_enqueue(st->safe_txq, (void *)resp_arp, resp_arp_size);
        ENET_BENCHMARK_STOP(2, "enqueue arp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to enqueue buffer");
            return err;
        }

        // store IP to MAC mapping of sender
        ENET_BENCHMARK_START(2, "update arp table on request")
        err = enet_update_arp_table(st, ntohl(arp->ip_src), arp->eth_src);
        ENET_BENCHMARK_STOP(2, "update arp table on request")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to update ARP table");
            return err;
        }

        break;
    case ARP_OP_REP:
        // store IP to MAC mapping
        ENET_BENCHMARK_START(2, "update arp table on response")
        err = enet_update_arp_table(st, ntohl(arp->ip_src), arp->eth_src);
        ENET_BENCHMARK_STOP(2, "update arp table on response")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to update ARP table");
            return err;
        }

        break;
    default:
        err = ENET_ERR_ARP_UNKNOWN_OPCODE;
        DEBUG_ERR(err, "unkown ARP opcode received: 0x%04x", ntohs(arp->opcode));
        return err;
    }

    return SYS_ERR_OK;
}


static errval_t enet_handle_icmp_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    struct icmp_echo_hdr *icmp = (struct icmp_echo_hdr *)((char *)ip + IP_HLEN);

    char *icmp_payload = (char *)icmp + ICMP_HLEN;
    size_t icmp_payload_size = ntohs(ip->len) - IP_HLEN - ICMP_HLEN;
    enet_debug_print_icmp_packet(icmp, icmp_payload_size);

    // control checksum
    if (inet_checksum(icmp, ICMP_HLEN + icmp_payload_size)) {
        ICMP_DEBUG("Dropping packet with invalid checksum: 0x%04x\n",
                   inet_checksum(icmp, ICMP_HLEN + icmp_payload_size));
        return SYS_ERR_OK;
    }

    ENET_BENCHMARK_INIT()
    // handle
    switch (icmp->type) {
    case ICMP_ER:
        ICMP_DEBUG("RECEIVED ICMP ECHO REPLY PACKET\n");

        ENET_BENCHMARK_START(3, "process icmp echo reply packet")
        err = enet_icmp_socket_handle_inbound(st, ntohl(ip->src), icmp->type,
                                              ntohs(icmp->id), ntohs(icmp->seqno),
                                              icmp_payload, icmp_payload_size);
        ENET_BENCHMARK_STOP(3, "process icmp echo reply packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle inbound ICMP packet");
            return err;
        }
        break;
    case ICMP_ECHO:
        ICMP_DEBUG("RECEIVED ICMP ECHO PACKET\n");
        struct eth_hdr *resp_icmp;
        size_t resp_icmp_size;
        ENET_BENCHMARK_START(3, "assemble icmp packet")
        err = enet_assemble_icmp_packet(enet_split_mac(st->mac), ENET_STATIC_IP, eth->src,
                                        ntohl(ip->src), ICMP_ER, ntohs(icmp->id),
                                        ntohs(icmp->seqno), icmp_payload,
                                        icmp_payload_size, &resp_icmp, &resp_icmp_size);
        ENET_BENCHMARK_STOP(3, "assemble icmp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to assemble ICMP packet");
            return err;
        }

        ENET_BENCHMARK_START(3, "enqueue icmp packet")
        err = safe_enqueue(st->safe_txq, (void *)resp_icmp, resp_icmp_size);
        ENET_BENCHMARK_STOP(3, "enqueue icmp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to enqueue buffer");
            return err;
        }

#ifdef ICMP_HACK
        // hack send packet
        err = enet_icmp_socket_send(st, ntohl(ip->src), ICMP_ECHO, 27, 27, NULL, 0);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to send");
            return err;
        }

        // HACK to read packet
        struct icmp_socket *hack_socket = st->icmp_socket;
        assert(hack_socket);

        struct icmp_socket_buf *buf;
        err = enet_icmp_socket_receive(st, &buf);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to receive");
            return err;
        }

        ICMP_DEBUG("from 0x%08x, id: %d seqno: %d\n", buf->ip, buf->id, buf->seqno);
        for (int i = 0; i < buf->len; i++) {
            ICMP_DEBUG("%02d: 0x%02x\n", i, ((char *)buf->data)[i]);
        }

#endif
        break;
    default:
        err = ENET_ERR_ICMP_UNKNOWN_TYPE;
        DEBUG_ERR(err, "unkown ICMP type received: 0x%04x", icmp->type);
        return err;
    }

    return SYS_ERR_OK;
}

__attribute__((unused)) static int enet_udp_send_hack(void *arg)
{
    errval_t err;

    struct enet_driver_state *st = (struct enet_driver_state *)arg;

    // HACK to read packet
    struct udp_socket *hack_socket = st->udp_sockets;
    while (hack_socket) {
        if (hack_socket->port == ENET_STATIC_PORT) {
            break;
        }
        hack_socket = hack_socket->next;
    }
    assert(hack_socket);

    struct udp_socket_buf *buf;
    err = enet_udp_socket_receive(st, hack_socket->port, &buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive");
        return err;
    }

    UDP_DEBUG("from 0x%08x %d\n", buf->ip, buf->port);
    for (int i = 0; i < buf->len; i++) {
        UDP_DEBUG("%02d: 0x%02x\n", i, ((char *)buf->data)[i]);
    }

    // hack send packet
    err = enet_udp_socket_send(st, ENET_STATIC_PORT, MK_IP(10, 42, 0, 1), 8051, buf->data,
                               buf->len);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send");
        return err;
    }

    return 0;
}

static errval_t enet_handle_udp_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    struct udp_hdr *udp = (struct udp_hdr *)((char *)ip + IP_HLEN);

    enet_debug_print_udp_packet(udp);

    char *udp_payload = (char *)udp + UDP_HLEN;
    size_t udp_payload_size = ntohs(udp->len) - UDP_HLEN;

    // UDP checksum seems to be broken
    // // control checksum
    // if (inet_checksum(udp, UDP_HLEN + udp_payload_size)) {
    //     UDP_DEBUG("Dropping packet with invalid checksum: 0x%04x\n",
    //               inet_checksum(udp, UDP_HLEN + udp_payload_size));
    //     return SYS_ERR_OK;
    // }

#ifdef UDP_ECHO
    // echo udp packet
    struct eth_hdr *resp_udp;
    size_t resp_udp_size;
    err = enet_assemble_udp_packet(enet_split_mac(st->mac), ENET_STATIC_IP,
                                   ENET_STATIC_PORT, eth->src, ntohl(ip->src),
                                   ntohs(udp->src), udp_payload, udp_payload_size,
                                   &resp_udp, &resp_udp_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble UDP packet");
        return err;
    }

    err = safe_enqueue(st->safe_txq, (void *)resp_udp, resp_udp_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to enqueue buffer");
        return err;
    }

    return SYS_ERR_OK;
#endif

    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(3, "process udp packet")
    err = enet_udp_socket_handle_inbound(st, ntohl(ip->src), ntohs(udp->src),
                                         ntohs(udp->dest), udp_payload, udp_payload_size);
    ENET_BENCHMARK_STOP(3, "process udp packet")
    if (err_is_fail(err)) {
        if (err == ENET_ERR_SOCKET_NOT_FOUND) {
            UDP_DEBUG("Destination unreachable (Port unreachable)\n");
            // TODO send back ICMP_DUR/ICMP_DUR_PORT
            return SYS_ERR_OK;
        }
        DEBUG_ERR(err, "failed to handle inbound UDP packet");
        return err;
    }

#ifdef UDP_HACK
    thread_create(enet_udp_send_hack, st);
#endif

    return SYS_ERR_OK;
}

static errval_t enet_handle_ip_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    enet_debug_print_ip_packet(ip);

    // IP packets is too small
    if (ip->len < IP_HLEN) {
        IP_DEBUG("Dropping undersized packet\n");
        return SYS_ERR_OK;
    }

    // only process IPv4 packets
    if (IPH_V(ip) != 4) {
        IP_DEBUG("Dropping non IPv4 packet\n");
        return SYS_ERR_OK;
    }

    // drop fragemented packets
    if (ip->offset & IP_MF) {
        IP_DEBUG("Dropping fragemented packets\n");
        return SYS_ERR_OK;
    }

    // control checksum
    if (inet_checksum(ip, IP_HLEN)) {
        IP_DEBUG("Dropping packet with invalid checksum\n");
        return SYS_ERR_OK;
    }

    ENET_BENCHMARK_INIT()
    switch (ip->proto) {
    case IP_PROTO_ICMP:
        ICMP_DEBUG("RECEIVED ICMP PACKET\n");
        ENET_BENCHMARK_START(2, "handle icmp packet")
        err = enet_handle_icmp_packet(st, eth);
        ENET_BENCHMARK_STOP(2, "handle icmp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle ICMP packet");
            return err;
        }
        break;
    case IP_PROTO_IGMP:
        DEBUG_PRINTF("RECEIVED IGMP PACKET\n");
        break;
    case IP_PROTO_UDP:
        UDP_DEBUG("RECEIVED UDP PACKET\n");
        ENET_BENCHMARK_START(2, "handle udp packet")
        err = enet_handle_udp_packet(st, eth);
        ENET_BENCHMARK_STOP(2, "handle udp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle UDP packet");
            return err;
        }
        break;
    case IP_PROTO_UDPLITE:
        DEBUG_PRINTF("RECEIVED UDP LITE PACKET\n");
        break;
    case IP_PROTO_TCP:
        DEBUG_PRINTF("RECEIVED TCP PACKET\n");
        break;
    default:
        err = ENET_ERR_IP_UNKOWN_PROTOCOL;
        DEBUG_ERR(err, "unkown IP protocol received: 0x%02x", ip->proto);
        return err;
    }

    return SYS_ERR_OK;
}

errval_t enet_handle_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    enet_debug_print_eth_packet(eth);

    ENET_BENCHMARK_INIT()
    switch (ntohs(eth->type)) {
    case ETH_TYPE_ARP:
        ETHARP_DEBUG("RECEIVED ARP PACKET\n");
        ENET_BENCHMARK_START(1, "handle arp packet")
        err = enet_handle_arp_packet(st, eth);
        ENET_BENCHMARK_STOP(1, "handle arp packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle ARP packet");
            return err;
        }
        break;
    case ETH_TYPE_IP:
        IP_DEBUG("RECEIVED IP PACKET\n");
        ENET_BENCHMARK_START(1, "handle ip packet")
        err = enet_handle_ip_packet(st, eth);
        ENET_BENCHMARK_STOP(1, "handle ip packet")
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle IP packet");
            return err;
        }
        break;
    default:
        err = ENET_ERR_UNKNOWN_ETH_HEADER;
        DEBUG_ERR(err, "unkown ethernet header type received: 0x%04x", ntohs(eth->type));
        return err;
    }

    return SYS_ERR_OK;
}