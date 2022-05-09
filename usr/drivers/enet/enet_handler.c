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
#include "enet_debug.h"

static struct region_entry *enet_get_region(struct region_entry *regions, uint32_t rid)
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

static void enet_split_mac(uint64_t mac, struct eth_addr *retmac)
{
    // TODO maybe reverse here already to network byte order
    retmac->addr[0] = (mac >> 40) & 0xFF;
    retmac->addr[1] = (mac >> 32) & 0xFF;
    retmac->addr[2] = (mac >> 24) & 0xFF;
    retmac->addr[3] = (mac >> 16) & 0xFF;
    retmac->addr[4] = (mac >> 8) & 0xFF;
    retmac->addr[5] = (mac >> 0) & 0xFF;
}

static errval_t enet_assemble_arp_packet(uint16_t opcode, struct eth_addr eth_src,
                                         uint32_t ip_src, struct eth_addr eth_dest,
                                         uint32_t ip_dest, struct arp_hdr *retarp)
{
    errval_t err;

    if (opcode != ARP_OP_REQ && opcode != ARP_OP_REP) {
        err = ENET_ERR_ARP_UNKNOWN_OPCODE;
        DEBUG_ERR(err, "unkown ARP operation");
        return err;
    }

    // harware type: ethernet
    retarp->hwtype = htons(ARP_HW_TYPE_ETH);
    retarp->hwlen = 6;
    // protocol type: IPv4
    retarp->proto = htons(ARP_PROT_IP);
    retarp->protolen = 4;

    // operation: request/response
    retarp->opcode = htons(opcode);

    // sender mac
    retarp->eth_src = eth_src;
    // sender ip
    retarp->ip_src = htonl(ip_src);
    // receiver mac
    retarp->eth_dst = eth_dest;
    // receiver ip
    retarp->ip_dst = htonl(ip_dest);

    enet_debug_print_arp_packet(retarp);

    return SYS_ERR_OK;
}

static errval_t enet_assemble_ip_packet(uint8_t protocol, uint16_t len,
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
    retip->offset = htons(0);
    // time to live
    retip->ttl = 128;
    // protocol: ICMP, IGMP, UDP, UDPLITE, TCP
    retip->proto = protocol;
    // checksum
    retip->chksum = htons(inet_checksum(retip, IP_HLEN));

    enet_debug_print_ip_packet(retip);

    return SYS_ERR_OK;
}

static errval_t enet_assemble_enet_packet(uint16_t type, struct eth_addr eth_src,
                                          struct eth_addr eth_dest, struct eth_hdr *reteth)
{
    // errval_t err;

    reteth->src = eth_src;
    reteth->dst = eth_dest;
    reteth->type = htons(type);

    // switch (type) {
    // case ETH_TYPE_ARP:
    //     break;
    // case ETH_TYPE_IP:
    //     break;
    // default:
    //     err = ENET_ERR_ETH_UNKNOWN_TYPE;
    //     DEBUG_ERR(err, "unkown ETH type");
    //     return err;
    // }

    enet_debug_print_eth_packet(reteth);

    return SYS_ERR_OK;
}

static errval_t enet_handle_arp_packet(struct enet_driver_state *st,
                                       struct eth_hdr *eth_header)
{
    // errval_t err;
    ENET_DEBUG("got ARP packet\n");

    struct arp_hdr *arp_header = (struct arp_hdr *)((char *)eth_header + ETH_HLEN);

    enet_debug_print_arp_packet(arp_header);

    // TODO handle requests/replies

    return SYS_ERR_OK;
}

static errval_t enet_handle_ip_packet(struct enet_driver_state *st,
                                      struct eth_hdr *eth_header)
{
    // errval_t err;
    ENET_DEBUG("got IP packet\n");

    struct ip_hdr *ip_header = (struct ip_hdr *)((char *)eth_header + ETH_HLEN);

    enet_debug_print_ip_packet(ip_header);

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

    struct eth_hdr *eth_header = (struct eth_hdr *)region->mem.vbase + packet->offset
                                 + packet->valid_data;

    // enet_debug_print_eth_packet(eth_header);

    switch (ntohs(eth_header->type)) {
    case ETH_TYPE_ARP:
        err = enet_handle_arp_packet(st, eth_header);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle ARP packet");
            return err;
        }
        break;
    case ETH_TYPE_IP:
        err = enet_handle_ip_packet(st, eth_header);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle IP packet");
            return err;
        }
        break;
    default:
        err = ENET_ERR_UNKNOWN_ETH_HEADER;
        DEBUG_ERR(err, "unkown ethernet header type received: 0x%04x",
                  ntohs(eth_header->type));
        return err;
    }

    return SYS_ERR_OK;
}