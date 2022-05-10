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

__attribute__((unused)) static errval_t
enet_assemble_ip_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                        struct eth_addr eth_dest, ip_addr_t ip_dest, uint8_t protocol,
                        uint16_t len, struct eth_hdr **retip, size_t *retip_size)
{
    errval_t err;

    if (protocol != IP_PROTO_ICMP && protocol != IP_PROTO_IGMP && protocol != IP_PROTO_UDP
        && protocol != IP_PROTO_UDPLITE && protocol != IP_PROTO_TCP) {
        err = ENET_ERR_IP_UNKOWN_PROTOCOL;
        DEBUG_ERR(err, "unkown IP protocol");
        return err;
    }

    struct eth_hdr *eth = (struct eth_hdr *)malloc(ETH_HLEN + IP_HLEN);
    err = enet_assemble_eth_packet(ETH_TYPE_IP, eth_src, eth_dest, eth);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble eth packet");
        return err;
    }

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);

    static uint16_t id = 0;

    // version and header len (stuffed): IPv4 and 20 bytes = 160 bits = 5*32 bits
    IPH_VHL_SET(ip, 4, 5);
    // quality of service
    ip->tos = 0;
    // total length
    ip->len = htons(len);
    // fragment id
    ip->id = htons(id++);
    // fragment offset
    ip->offset = htons(0);
    // time to live
    ip->ttl = 128;
    // protocol: ICMP, IGMP, UDP, UDPLITE, TCP
    ip->proto = protocol;
    // checksum
    ip->chksum = htons(inet_checksum(ip, IP_HLEN));

    ip->src = ip_src;
    ip->dest = ip_dest;

    enet_debug_print_ip_packet(ip);

    *retip = eth;
    *retip_size = ETH_HLEN + IP_HLEN;

    return SYS_ERR_OK;
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

        // TODO store ip->mac mapping of sender

        break;
    case ARP_OP_REP:;  // empty statement
        // store IP to MAC mapping
        uint64_t *eth_src = malloc(sizeof(uint64_t));
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

static errval_t enet_handle_ip_packet(struct enet_driver_state *st, struct eth_hdr *eth)
{
    // errval_t err;

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);

    enet_debug_print_eth_packet(eth);
    enet_debug_print_ip_packet(ip);

    // TODO handle requests/replies

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