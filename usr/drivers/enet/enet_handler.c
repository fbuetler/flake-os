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

#include "enet.h"

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

void enet_debug_print_mac(struct eth_addr mac)
{
    ENET_DEBUG("%02x:%02x:%02x:%02x:%02x:%02x\n", mac.addr[0], mac.addr[1], mac.addr[2],
               mac.addr[3], mac.addr[4], mac.addr[5]);
}

void enet_debug_print_eth_packet(struct eth_hdr *eth, size_t eth_len)
{
    ENET_DEBUG("ETH dest MAC: ");
    enet_debug_print_mac(eth->dst);

    ENET_DEBUG("ETH src MAC: ");  // 3c:18:a0:b3:ed:06
    enet_debug_print_mac(eth->src);

    ENET_DEBUG("ETH type: %04x\n", ntohs(eth->type));

    ENET_DEBUG("ETH data: (%d)\n", eth_len);
    // char *data = (char *)eth;
    // for (int i = ETH_HLEN; i < eth_len; i++) {
    //     ENET_DEBUG("%d: 0x%x\n", i, data[i]);
    // }
}

void enet_debug_print_arp_packet(struct arp_hdr *arp, size_t arp_len)
{
    ENET_DEBUG("ARP data: (%d)\n", arp_len);
    // char *data = (char *)arp;
    // for (int i = ARP_HLEN; i < arp_len; i++) {
    //     ENET_DEBUG("%d: 0x%x\n", i, data[i]);
    // }
}

void enet_debug_print_ip_packet(struct ip_hdr *ip, size_t ip_len)
{
    ENET_DEBUG("IP verion/header length: 0x%x\n", ip->v_hl);
    ENET_DEBUG("IP type: 0x%x\n", ip->tos);
    ENET_DEBUG("IP total length: 0x%02x\n", ntohs(ip->len));
    ENET_DEBUG("IP id: 0x%02x\n", ntohs(ip->id));
    ENET_DEBUG("IP fragement offset: 0x%02x\n", ntohs(ip->offset));
    ENET_DEBUG("IP TTL: 0x%x\n", ip->ttl);
    ENET_DEBUG("IP proto: 0x%x\n", ip->proto);
    ENET_DEBUG("IP checksum: 0x%02x\n", ntohs(ip->chksum));

    ip_addr_t src = ntohl(ip->src);
    ip_addr_t dest = ntohl(ip->dest);
    ENET_DEBUG("IP src: %d.%d.%d.%d\n", (src >> 24) & 0xFF, (src >> 16) & 0xFF,
               (src >> 8) & 0xFF, src & 0xFF);
    ENET_DEBUG("IP dest: %d.%d.%d.%d\n", (dest >> 24) & 0xFF, (dest >> 16) & 0xFF,
               (dest >> 8) & 0xFF, dest & 0xFF);

    ENET_DEBUG("IP data: (%d)\n", ip_len);
    // char *data = (char *)ip;
    // for (int i = IP_HLEN; i < ip_len; i++) {
    //     ENET_DEBUG("%d: 0x%x\n", i, data[i]);
    // }
}

static errval_t enet_handle_arp_packet(struct enet_driver_state *st,
                                       struct eth_hdr *eth_header, size_t eth_len)
{
    // errval_t err;
    ENET_DEBUG("got ARP packet\n");

    struct arp_hdr *arp_header = (struct arp_hdr *)((char *)eth_header + ETH_HLEN);
    size_t arp_len = eth_len;

    enet_debug_print_arp_packet(arp_header, arp_len);

    // TODO handle requests/replies

    return SYS_ERR_OK;
}

static errval_t enet_handle_ip_packet(struct enet_driver_state *st,
                                      struct eth_hdr *eth_header, size_t eth_len)
{
    // errval_t err;
    ENET_DEBUG("got IP packet\n");

    struct ip_hdr *ip_header = (struct ip_hdr *)((char *)eth_header + ETH_HLEN);
    size_t ip_len = eth_len;

    enet_debug_print_ip_packet(ip_header, ip_len);

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
    size_t eth_len = packet->valid_length;

    // enet_debug_print_eth_packet(eth_header, eth_len);

    switch (ntohs(eth_header->type)) {
    case ETH_TYPE_ARP:
        err = enet_handle_arp_packet(st, eth_header, eth_len);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to handle ARP packet");
            return err;
        }
        break;
    case ETH_TYPE_IP:
        err = enet_handle_ip_packet(st, eth_header, eth_len);
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