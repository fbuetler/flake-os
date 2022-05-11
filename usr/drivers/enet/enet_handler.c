#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>
#include <netutil/etharp.h>
#include <netutil/htons.h>
#include <netutil/checksum.h>

#include "enet.h"
#include "enet_safe_queue.h"
#include "enet_debug.h"

struct region_entry *enet_get_region(struct region_entry *regions, uint32_t rid)
{
    struct region_entry *r = regions;
    while (r != NULL) {
        if (r->rid == rid) {
            return r;
        }
        r = r->next;
    }
    return NULL;
}

static struct eth_addr enet_split_mac(uint64_t mac)
{
    return (struct eth_addr) { .addr = { ((mac >> 40) & 0xFF), ((mac >> 32) & 0xFF),
                                         ((mac >> 24) & 0xFF), ((mac >> 16) & 0xFF),
                                         ((mac >> 8) & 0xFF), ((mac >> 0) & 0xFF) } };
}

static uint64_t enet_fuse_mac(struct eth_addr mac)
{
    return ((uint64_t)mac.addr[0] << 40) | ((uint64_t)mac.addr[1] << 32)
           | ((uint64_t)mac.addr[2] << 24) | ((uint64_t)mac.addr[3] << 16)
           | ((uint64_t)mac.addr[4] << 8) | ((uint64_t)mac.addr[5] << 0);
}

static errval_t enet_assemble_eth_packet(uint16_t type, struct eth_addr eth_src,
                                         struct eth_addr eth_dest, struct eth_hdr *reteth)
{
    reteth->src = eth_src;
    reteth->dst = eth_dest;
    reteth->type = htons(type);

    enet_debug_print_eth_packet(reteth);

    return SYS_ERR_OK;
}

static errval_t enet_assemble_arp_packet(uint16_t opcode, struct eth_addr eth_src,
                                         ip_addr_t ip_src, struct eth_addr eth_dest,
                                         ip_addr_t ip_dest, struct eth_hdr **retarp,
                                         size_t *retarp_size)
{
    errval_t err;

    if (opcode != ARP_OP_REQ && opcode != ARP_OP_REP) {
        err = ENET_ERR_ARP_UNKNOWN_OPCODE;
        DEBUG_ERR(err, "unkown ARP operation");
        return err;
    }

    struct eth_hdr *eth = (struct eth_hdr *)malloc(ETH_HLEN + ARP_HLEN);
    err = enet_assemble_eth_packet(ETH_TYPE_ARP, eth_src, eth_dest, eth);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble eth packet");
        return err;
    }

    struct arp_hdr *arp = (struct arp_hdr *)((char *)eth + ETH_HLEN);

    // harware type: ethernet
    arp->hwtype = htons(ARP_HW_TYPE_ETH);
    arp->hwlen = 6;
    // protocol type: IPv4
    arp->proto = htons(ARP_PROT_IP);
    arp->protolen = 4;

    // operation: request/response
    arp->opcode = htons(opcode);

    // sender mac
    arp->eth_src = eth_src;
    // sender ip
    arp->ip_src = htonl(ip_src);
    // receiver mac
    arp->eth_dst = eth_dest;
    // receiver ip
    arp->ip_dst = htonl(ip_dest);

    enet_debug_print_arp_packet(arp);

    *retarp = eth;
    *retarp_size = ETH_HLEN + ARP_HLEN;

    return SYS_ERR_OK;
}

static errval_t enet_assemble_ip_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                        struct eth_addr eth_dest, ip_addr_t ip_dest,
                                        uint8_t protocol, uint16_t len,
                                        struct ip_hdr *retip)
{
    errval_t err;

    if (protocol != IP_PROTO_ICMP && protocol != IP_PROTO_IGMP && protocol != IP_PROTO_UDP
        && protocol != IP_PROTO_UDPLITE && protocol != IP_PROTO_TCP) {
        err = ENET_ERR_IP_UNKOWN_PROTOCOL;
        DEBUG_ERR(err, "unkown IP protocol");
        return err;
    }

    static uint16_t id = 0;

    // version and header len (stuffed): IPv4 and 20 bytes = 160 bits = 5*32 bits
    IPH_VHL_SET(retip, 4, 5);
    // quality of service
    retip->tos = 0;
    // total length
    retip->len = htons(len);
    // fragment id
    retip->id = htons(id++);
    // fragment offset
    retip->offset = htons(IP_DF);
    // time to live
    retip->ttl = 128;
    // protocol: ICMP, IGMP, UDP, UDPLITE, TCP
    retip->proto = protocol;
    // source/dest IP
    retip->src = htonl(ip_src);
    retip->dest = htonl(ip_dest);
    // checksum
    retip->chksum = 0;
    retip->chksum = inet_checksum(retip, IP_HLEN);


    enet_debug_print_ip_packet(retip);

    return SYS_ERR_OK;
}

static errval_t enet_assemble_icmp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                          struct eth_addr eth_dest, ip_addr_t ip_dest,
                                          uint8_t type, uint16_t id, uint16_t seqno,
                                          char *payload, size_t payload_size,
                                          struct eth_hdr **reticmp, size_t *reticmp_size)
{
    errval_t err;

    if (type != ICMP_ER && type != ICMP_ECHO) {
        err = ENET_ERR_ICMP_UNKNOWN_TYPE;
        DEBUG_ERR(err, "unkown ICMP type");
        return err;
    }

    struct eth_hdr *eth = (struct eth_hdr *)malloc(ETH_HLEN + IP_HLEN + ICMP_HLEN
                                                   + payload_size);
    err = enet_assemble_eth_packet(ETH_TYPE_IP, eth_src, eth_dest, eth);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble ETH packet");
        return err;
    }

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    err = enet_assemble_ip_packet(eth_src, ip_src, eth_dest, ip_dest, IP_PROTO_ICMP,
                                  IP_HLEN + ICMP_HLEN + payload_size, ip);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble IP packet");
        return err;
    }

    struct icmp_echo_hdr *icmp = (struct icmp_echo_hdr *)((char *)ip + IP_HLEN);

    icmp->type = type;
    icmp->code = 0;
    icmp->id = htons(id);
    icmp->seqno = htons(seqno);
    memcpy((char *)icmp + ICMP_HLEN, payload, payload_size);

    icmp->chksum = 0;
    icmp->chksum = inet_checksum(icmp, ICMP_HLEN + payload_size);

    enet_debug_print_icmp_packet(icmp);
    ICMP_DEBUG("ICMP payload size: 0x%lx\n", payload_size);

    *reticmp = eth;
    *reticmp_size = ETH_HLEN + IP_HLEN + ICMP_HLEN + payload_size;

    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t enet_get_mac_by_ip(struct enet_driver_state *st,
                                                           ip_addr_t ip_dest,
                                                           struct eth_addr *retmac)
{
    errval_t err;

    // get from cache if available
    uint64_t *mac = (uint64_t *)collections_hash_find(st->arp_table, ip_dest);
    if (mac) {
        *retmac = enet_split_mac(*mac);
        return SYS_ERR_OK;
    }

    // otherwise broadcast request
    struct eth_hdr *arp;
    size_t arp_size;
    err = enet_assemble_arp_packet(ARP_OP_REQ, enet_split_mac(st->mac), ENET_STATIC_IP,
                                   enet_split_mac(ETH_BROADCAST), ip_dest, &arp,
                                   &arp_size);
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

static errval_t enet_handle_arp_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct arp_hdr *arp = (struct arp_hdr *)((char *)eth + ETH_HLEN);

    enet_debug_print_eth_packet(eth);
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
        err = enet_assemble_arp_packet(ARP_OP_REP, enet_split_mac(st->mac),
                                       ENET_STATIC_IP, arp->eth_src, ntohl(arp->ip_src),
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

        // store ip->mac mapping of sender
        uint64_t *eth_src = (uint64_t *)malloc(sizeof(uint64_t));
        *eth_src = enet_fuse_mac(arp->eth_src);
        if (collections_hash_find(st->arp_table, arp->ip_src)) {
            collections_hash_delete(st->arp_table, arp->ip_src);
            collections_hash_insert(st->arp_table, arp->ip_src, eth_src);
        } else {
            collections_hash_insert(st->arp_table, arp->ip_src, eth_src);
        }

        enet_debug_print_arp_table(st->arp_table);

        break;
    case ARP_OP_REP:;  // empty statement
        // store IP to MAC mapping
        eth_src = (uint64_t *)malloc(sizeof(uint64_t));
        *eth_src = enet_fuse_mac(arp->eth_src);
        if (collections_hash_find(st->arp_table, arp->ip_src)) {
            collections_hash_delete(st->arp_table, arp->ip_src);
            collections_hash_insert(st->arp_table, arp->ip_src, eth_src);
        } else {
            collections_hash_insert(st->arp_table, arp->ip_src, eth_src);
        }

        enet_debug_print_arp_table(st->arp_table);

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

    enet_debug_print_icmp_packet(icmp);

    char *icmp_payload = (char *)icmp + ICMP_HLEN;
    size_t icmp_payload_size = ntohs(ip->len) - IP_HLEN - ICMP_HLEN;
    ICMP_DEBUG("ICMP payload size: 0x%lx\n", icmp_payload_size);

    // control checksum
    if (inet_checksum(icmp, ICMP_HLEN + icmp_payload_size)) {
        ICMP_DEBUG("Dropping packet with invalid checksum: 0x%04x\n",
                   inet_checksum(icmp, ICMP_HLEN));
        return SYS_ERR_OK;
    }

    // handle
    switch (icmp->type) {
    case ICMP_ER:
        DEBUG_PRINTF("RECEIVED ICMP ECHO REPLY PACKET\n");
        break;
    case ICMP_ECHO:
        DEBUG_PRINTF("RECEIVED ICMP ECHO PACKET\n");
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

static errval_t enet_handle_ip_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    errval_t err;

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);

    enet_debug_print_eth_packet(eth);
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
        DEBUG_PRINTF("RECEIVED ICMP PACKET\n");
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
        DEBUG_PRINTF("RECEIVED UDP PACKET\n");
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

errval_t enet_handle_packet(struct enet_driver_state *st, struct devq_buf *packet)
{
    errval_t err;

    struct region_entry *region = enet_get_region(st->rxq->regions, packet->rid);
    if (!region) {
        err = ENET_ERR_REGION_NOT_FOUND;
        DEBUG_ERR(err, "failed to find region");
        return err;
    }

    struct eth_hdr *eth = (struct eth_hdr *)((char *)region->mem.vbase + packet->offset
                                             + packet->valid_data);

    // enet_debug_print_eth_packet(eth);

    switch (ntohs(eth->type)) {
    case ETH_TYPE_ARP:
        DEBUG_PRINTF("RECEIVED ARP PACKET\n");
        err = enet_handle_arp_packet(st, eth);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle ARP packet");
            return err;
        }
        break;
    case ETH_TYPE_IP:
        DEBUG_PRINTF("RECEIVED IP PACKET\n");
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