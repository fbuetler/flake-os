#include <aos/aos.h>

#include <netutil/htons.h>
#include <netutil/checksum.h>

#include "enet.h"
#include "enet_safe_queue.h"
#include "enet_debug.h"
#include "enet_assembler.h"

// #define UDP_ECHO 1

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
    enet_debug_print_arp_table(st->arp_table);
    uint64_t *mac = (uint64_t *)collections_hash_find(st->arp_table, ip_dest);
    if (mac) {
        *retmac = enet_split_mac(*mac);
        return SYS_ERR_OK;
    }

    // otherwise broadcast request
    struct eth_hdr *arp;
    size_t arp_size;
    err = enet_assemble_arp_packet(enet_split_mac(st->mac), ENET_STATIC_IP,
                                   enet_split_mac(ETH_BROADCAST), ip_dest, ARP_OP_REQ,
                                   &arp, &arp_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble arp packet");
        return err;
    }

    err = safe_enqueue(st->safe_txq, (void *)arp, arp_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to enqueue buffer");
        return err;
    }

    /*
    // wait until response is here
    size_t retries = 0;
    size_t max_retries = 512;
    while (retries < max_retries) {
        mac = (uint64_t *)collections_hash_find(st->arp_table, ip_dest);
        if (mac) {
            *retmac = enet_split_mac(*mac);
            return SYS_ERR_OK;
        }
        retries++;
        barrelfish_usleep(1000);
    }
    */

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
        err = enet_assemble_arp_packet(enet_split_mac(st->mac), ENET_STATIC_IP,
                                       arp->eth_src, ntohl(arp->ip_src), ARP_OP_REP,
                                       &resp_arp, &resp_arp_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to assemble arp packet");
            return err;
        }

        err = safe_enqueue(st->safe_txq, (void *)resp_arp, resp_arp_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to enqueue buffer");
            return err;
        }

        // store IP to MAC mapping of sender
        err = enet_update_arp_table(st, ntohl(arp->ip_src), arp->eth_src);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to update ARP table");
            return err;
        }

        break;
    case ARP_OP_REP:
        // store IP to MAC mapping
        err = enet_update_arp_table(st, ntohl(arp->ip_src), arp->eth_src);
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

    // handle
    switch (icmp->type) {
    case ICMP_ER:
        ICMP_DEBUG("RECEIVED ICMP ECHO REPLY PACKET\n");
        // TODO handle
        break;
    case ICMP_ECHO:
        ICMP_DEBUG("RECEIVED ICMP ECHO PACKET\n");
        struct eth_hdr *resp_icmp;
        size_t resp_icmp_size;
        err = enet_assemble_icmp_packet(enet_split_mac(st->mac), ENET_STATIC_IP, eth->src,
                                        ntohl(ip->src), ICMP_ER, ntohs(icmp->id),
                                        ntohs(icmp->seqno), icmp_payload,
                                        icmp_payload_size, &resp_icmp, &resp_icmp_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to assemble ICMP packet");
            return err;
        }

        err = safe_enqueue(st->safe_txq, (void *)resp_icmp, resp_icmp_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to enqueue buffer");
            return err;
        }
        break;
    default:
        err = ENET_ERR_ICMP_UNKNOWN_TYPE;
        DEBUG_ERR(err, "unkown ICMP type received: 0x%04x", icmp->type);
        return err;
    }

    return SYS_ERR_OK;
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

    err = enet_socket_handle_inbound(st, ntohl(ip->src), ntohs(udp->src),
                                     ntohs(udp->dest), udp_payload, udp_payload_size);
    if (err_is_fail(err)) {
        if (err == ENET_ERR_SOCKET_NOT_FOUND) {
            UDP_DEBUG("Destination unreachable (Port unreachable)\n");
            // TODO send back ICMP_DUR/ICMP_DUR_PORT
            return SYS_ERR_OK;
        }
        DEBUG_ERR(err, "failed to handle inbound UDP packet");
        return err;
    }
    return SYS_ERR_OK;
}

static errval_t enet_handle_ip_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    enet_debug_print_ip_packet(ip);

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

    switch (ip->proto) {
    case IP_PROTO_ICMP:
        ICMP_DEBUG("RECEIVED ICMP PACKET\n");
        err = enet_handle_icmp_packet(st, eth);
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
        err = enet_handle_udp_packet(st, eth);
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

    switch (ntohs(eth->type)) {
    case ETH_TYPE_ARP:
        ETHARP_DEBUG("RECEIVED ARP PACKET\n");
        err = enet_handle_arp_packet(st, eth);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle ARP packet");
            return err;
        }
        break;
    case ETH_TYPE_IP:
        IP_DEBUG("RECEIVED IP PACKET\n");
        err = enet_handle_ip_packet(st, eth);
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