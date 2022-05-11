

#ifndef ENET_DEBUG_H_
#define ENET_DEBUG_H_

#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/icmp.h>
#include <netutil/udp.h>
#include <collections/hash_table.h>

void enet_debug_print_mac(struct eth_addr mac);
void enet_debug_print_ip(ip_addr_t ip);

void enet_debug_print_eth_packet(struct eth_hdr *eth);
void enet_debug_print_arp_packet(struct arp_hdr *arp);
void enet_debug_print_ip_packet(struct ip_hdr *ip);
void enet_debug_print_icmp_packet(struct icmp_echo_hdr *icmp);

void enet_debug_print_arp_table(collections_hash_table *arp_table);

#endif  // ndef ENET_DEBUG_H_