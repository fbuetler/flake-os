/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */
#ifndef ENET_ASSEMBLER_H_
#define ENET_ASSEMBLER_H_ 1

#include <aos/aos.h>

#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/icmp.h>
#include <netutil/udp.h>
#include <netutil/htons.h>
#include <netutil/checksum.h>

errval_t enet_assemble_eth_packet(uint16_t type, struct eth_addr eth_src,
                                  struct eth_addr eth_dest, struct eth_hdr *reteth);

errval_t enet_assemble_arp_packet(uint16_t opcode, struct eth_addr eth_src,
                                  ip_addr_t ip_src, struct eth_addr eth_dest,
                                  ip_addr_t ip_dest, struct eth_hdr **retarp,
                                  size_t *retarp_size);

errval_t enet_assemble_ip_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                 struct eth_addr eth_dest, ip_addr_t ip_dest,
                                 uint8_t protocol, uint16_t len, struct ip_hdr *retip);

errval_t enet_assemble_icmp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                   struct eth_addr eth_dest, ip_addr_t ip_dest,
                                   uint8_t type, uint16_t id, uint16_t seqno,
                                   char *payload, size_t payload_size,
                                   struct eth_hdr **reticmp, size_t *reticmp_size);

#endif /* ENET_ASSEMBLER_H_ */