
#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>

#include <netutil/htons.h>
#include <netutil/checksum.h>

#include "enet.h"
#include "enet_debug.h"

static char buf[1024];

__attribute__((unused)) static char *enet_print_mac(struct eth_addr mac)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac.addr[0], mac.addr[1], mac.addr[2],
            mac.addr[3], mac.addr[4], mac.addr[5]);
    return buf;
}

void enet_debug_print_mac(struct eth_addr mac)
{
    ETHARP_DEBUG("%s\n", enet_print_mac(mac));
}

__attribute__((unused)) static char *enet_print_ip(ip_addr_t ip)
{
    sprintf(buf, "%d.%d.%d.%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF,
            ip & 0xFF);
    return buf;
}

void enet_debug_print_ip(ip_addr_t ip)
{
    IP_DEBUG("%s\n", enet_print_ip(ip));
}

void enet_debug_print_eth_packet(struct eth_hdr *eth)
{
    ETHARP_DEBUG("ETH src MAC: %s\n",
                 enet_print_mac(eth->src));  // laptop: 3c:18:a0:b3:ed:06
    ETHARP_DEBUG("ETH dest MAC: %s\n",
                 enet_print_mac(eth->dst));  // board: 00:14:2d:64:13:cd
    ETHARP_DEBUG("ETH type: %04x\n", ntohs(eth->type));
}

void enet_debug_print_arp_packet(struct arp_hdr *arp)
{
    ETHARP_DEBUG("ARP hw type: 0x%04x\n", ntohs(arp->hwtype));
    ETHARP_DEBUG("ARP proto: 0x%04x\n", ntohs(arp->proto));
    ETHARP_DEBUG("ARP hw len: 0x%02x\n", arp->hwlen);
    ETHARP_DEBUG("ARP proto len: 0x%02x\n", arp->protolen);
    ETHARP_DEBUG("ARP op code: 0x%04x\n", ntohs(arp->opcode));

    ETHARP_DEBUG("ARP eth src: %s\n", enet_print_mac(arp->eth_src));
    ETHARP_DEBUG("ARP ip src: %s\n", enet_print_ip(ntohl(arp->ip_src)));
    ETHARP_DEBUG("ARP eth dest: %s\n", enet_print_mac(arp->eth_dst));
    ETHARP_DEBUG("ARP ip dest: %s\n", enet_print_ip(ntohl(arp->ip_dst)));
}

void enet_debug_print_ip_packet(struct ip_hdr *ip)
{
    IP_DEBUG("IP version/header length: 0x%02x\n", ip->v_hl);
    IP_DEBUG("IP type: 0x%02x\n", ip->tos);
    IP_DEBUG("IP total length: 0x%04x\n", ntohs(ip->len));
    IP_DEBUG("IP id: 0x%04x\n", ntohs(ip->id));
    IP_DEBUG("IP fragement offset: 0x%04x\n", ntohs(ip->offset));
    IP_DEBUG("IP TTL: 0x%02x\n", ip->ttl);
    IP_DEBUG("IP protocol: 0x%02x\n", ip->proto);
    IP_DEBUG("IP checksum: 0x%04x\n", ntohs(ip->chksum));

    IP_DEBUG("IP src: %s\n", enet_print_ip(ntohl(ip->src)));
    IP_DEBUG("IP dest: %s\n", enet_print_ip(ntohl(ip->dest)));
}

void enet_debug_print_icmp_packet(struct icmp_echo_hdr *icmp)
{
    ICMP_DEBUG("ICMP type: %02x\n", icmp->type);
    ICMP_DEBUG("ICMP code: %02x\n", icmp->code);
    ICMP_DEBUG("ICMP chksum: %04x\n", ntohs(icmp->chksum));
    ICMP_DEBUG("ICMP id: %04x\n", ntohs(icmp->id));
    ICMP_DEBUG("ICMP seqno: %04x\n", ntohs(icmp->seqno));
}

void enet_debug_print_arp_table(collections_hash_table *arp_table)
{
    if (collections_hash_traverse_start(arp_table) == -1) {
        ETHARP_DEBUG("Failed to print ARP table\n");
        return;
    }

    uint64_t ip;
    uint64_t *eth;
    ETHARP_DEBUG("=============== ARP table ===============\n");
    do {
        eth = (uint64_t *)collections_hash_traverse_next(arp_table, &ip);
        if (!eth) {
            break;
        }

        ip = ntohl(ip);
        ETHARP_DEBUG("%d.%d.%d.%d - %02x:%02x:%02x:%02x:%02x:%02x\n", (ip >> 24) & 0xFF,
                     (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                     ((*eth >> 40) & 0xFF), ((*eth >> 32) & 0xFF), ((*eth >> 24) & 0xFF),
                     ((*eth >> 16) & 0xFF), ((*eth >> 8) & 0xFF), ((*eth >> 0) & 0xFF));
    } while (1);
    ETHARP_DEBUG("=========================================\n");

    collections_hash_traverse_end(arp_table);
}