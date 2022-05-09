

#ifndef ENET_DEBUG_H_
#define ENET_DEBUG_H_

#include <netutil/etharp.h>
#include <netutil/ip.h>

void enet_debug_print_mac(struct eth_addr mac);
void enet_debug_print_eth_packet(struct eth_hdr *eth);
void enet_debug_print_arp_packet(struct arp_hdr *arp);
void enet_debug_print_ip_packet(struct ip_hdr *ip);

#endif  // ndef ENET_DEBUG_H_