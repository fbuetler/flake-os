
#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>

#include <netutil/htons.h>
#include <netutil/checksum.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>

#include "enet.h"
#include "enet_debug.h"

void enet_debug_print_mac(struct eth_addr mac)
{
    ENET_DEBUG("%02x:%02x:%02x:%02x:%02x:%02x\n", mac.addr[0], mac.addr[1], mac.addr[2],
               mac.addr[3], mac.addr[4], mac.addr[5]);
}

void enet_debug_print_eth_packet(struct eth_hdr *eth)
{
    ENET_DEBUG("ETH src MAC: ");  // laptop: 3c:18:a0:b3:ed:06
    enet_debug_print_mac(eth->src);

    ENET_DEBUG("ETH dest MAC: ");
    enet_debug_print_mac(eth->dst);  // board: 00:14:2d:64:13:cd

    ENET_DEBUG("ETH type: %04x\n", ntohs(eth->type));
}

void enet_debug_print_arp_packet(struct arp_hdr *arp)
{
    ENET_DEBUG("ARP hw type: 0x%04x\n", ntohs(arp->hwtype));
    ENET_DEBUG("ARP proto: 0x%04x\n", ntohs(arp->proto));
    ENET_DEBUG("ARP hw len: 0x%02x\n", arp->hwlen);
    ENET_DEBUG("ARP proto len: 0x%02x\n", arp->protolen);
    ENET_DEBUG("ARP op code: 0x%04x\n", ntohs(arp->opcode));

    ip_addr_t src = ntohl(arp->ip_src);
    ip_addr_t dest = ntohl(arp->ip_dst);
    ENET_DEBUG("ARP eth src:");
    enet_debug_print_mac(arp->eth_src);
    ENET_DEBUG("ARP ip src: %d.%d.%d.%d\n", (src >> 24) & 0xFF, (src >> 16) & 0xFF,
               (src >> 8) & 0xFF, src & 0xFF);
    ENET_DEBUG("ARP eth dest:");
    enet_debug_print_mac(arp->eth_dst);
    ENET_DEBUG("ARP ip dest: %d.%d.%d.%d\n", (dest >> 24) & 0xFF, (dest >> 16) & 0xFF,
               (dest >> 8) & 0xFF, dest & 0xFF);
}

void enet_debug_print_ip_packet(struct ip_hdr *ip)
{
    ENET_DEBUG("IP verion/header length: 0x%02x\n", ip->v_hl);
    ENET_DEBUG("IP type: 0x%02x\n", ip->tos);
    ENET_DEBUG("IP total length: 0x%04x\n", ntohs(ip->len));
    ENET_DEBUG("IP id: 0x%04x\n", ntohs(ip->id));
    ENET_DEBUG("IP fragement offset: 0x%04x\n", ntohs(ip->offset));
    ENET_DEBUG("IP TTL: 0x%02x\n", ip->ttl);
    ENET_DEBUG("IP protocol: 0x%02x\n", ip->proto);
    ENET_DEBUG("IP checksum: 0x%04x\n", ntohs(ip->chksum));

    ip_addr_t src = ntohl(ip->src);
    ip_addr_t dest = ntohl(ip->dest);
    ENET_DEBUG("IP src: %d.%d.%d.%d\n", (src >> 24) & 0xFF, (src >> 16) & 0xFF,
               (src >> 8) & 0xFF, src & 0xFF);
    ENET_DEBUG("IP dest: %d.%d.%d.%d\n", (dest >> 24) & 0xFF, (dest >> 16) & 0xFF,
               (dest >> 8) & 0xFF, dest & 0xFF);
}

void enet_debug_print_arp_table(collections_hash_table *arp_table)
{
    if (collections_hash_traverse_start(arp_table) == -1) {
        ENET_DEBUG("Failed to print ARP table\n");
        return;
    }

    uint64_t ip;
    uint64_t *eth;
    ENET_DEBUG("=============== ARP table ===============\n");
    do {
        eth = (uint64_t *)collections_hash_traverse_next(arp_table, &ip);
        if (!eth) {
            break;
        }

        ip = ntohl(ip);
        ENET_DEBUG("%d.%d.%d.%d - %02x:%02x:%02x:%02x:%02x:%02x\n", (ip >> 24) & 0xFF,
                   (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, ((*eth >> 40) & 0xFF),
                   ((*eth >> 32) & 0xFF), ((*eth >> 24) & 0xFF), ((*eth >> 16) & 0xFF),
                   ((*eth >> 8) & 0xFF), ((*eth >> 0) & 0xFF));
    } while (1);
    ENET_DEBUG("=========================================\n");

    collections_hash_traverse_end(arp_table);
}