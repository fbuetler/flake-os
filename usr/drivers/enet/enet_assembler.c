
#include "enet_assembler.h"
#include "enet_debug.h"

// #define ENET_ASSEMBLER_DEBUG_OPTION 1

#if defined(ENET_ASSEMBLER_DEBUG_OPTION)
#    define ASSEMBLER_DEBUG(x...) debug_printf("[assemble] " x);
#else
#    define ASSEMBLER_DEBUG(fmt, ...) ((void)0)
#endif

// TODO refactor packet assembly line
errval_t enet_assemble_eth_packet(uint16_t type, struct eth_addr eth_src,
                                  struct eth_addr eth_dest, struct eth_hdr *reteth)
{
    reteth->src = eth_src;
    reteth->dst = eth_dest;
    reteth->type = htons(type);

    enet_debug_print_eth_packet(reteth);

    return SYS_ERR_OK;
}

errval_t enet_assemble_arp_packet(uint16_t opcode, struct eth_addr eth_src,
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

errval_t enet_assemble_ip_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                 struct eth_addr eth_dest, ip_addr_t ip_dest,
                                 uint8_t protocol, uint16_t len, struct ip_hdr *retip)
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

errval_t enet_assemble_icmp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
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
