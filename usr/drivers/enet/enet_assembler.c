
#include "enet.h"
#include "enet_assembler.h"
#include "enet_debug.h"

static errval_t enet_create_eth_packet(struct eth_addr eth_src, struct eth_addr eth_dest,
                                       uint16_t type, struct eth_hdr *eth)
{
    eth->src = eth_src;
    eth->dst = eth_dest;
    eth->type = htons(type);

    enet_debug_print_eth_packet(eth);

    return SYS_ERR_OK;
}

static errval_t enet_create_arp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                       struct eth_addr eth_dest, ip_addr_t ip_dest,
                                       uint16_t opcode, struct arp_hdr *arp)
{
    errval_t err;

    if (opcode != ARP_OP_REQ && opcode != ARP_OP_REP) {
        err = ENET_ERR_ARP_UNKNOWN_OPCODE;
        DEBUG_ERR(err, "unkown ARP operation");
        return err;
    }

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

    return SYS_ERR_OK;
}

static errval_t enet_create_ip_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                      struct eth_addr eth_dest, ip_addr_t ip_dest,
                                      uint8_t protocol, uint16_t payload_size,
                                      struct ip_hdr *ip)
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
    IPH_VHL_SET(ip, 4, 5);
    // quality of service
    ip->tos = 0;
    // total length
    ip->len = htons(IP_HLEN + payload_size);
    // fragment id
    ip->id = htons(id++);
    // fragment offset
    ip->offset = htons(IP_DF);
    // time to live
    ip->ttl = 128;
    // protocol: ICMP, IGMP, UDP, UDPLITE, TCP
    ip->proto = protocol;
    // source/dest IP
    ip->src = htonl(ip_src);
    ip->dest = htonl(ip_dest);
    // checksum
    ip->chksum = 0;
    ip->chksum = inet_checksum(ip, IP_HLEN);

    enet_debug_print_ip_packet(ip);

    return SYS_ERR_OK;
}

static errval_t enet_create_icmp_packet(uint8_t type, uint16_t id, uint16_t seqno,
                                        char *payload, size_t payload_size,
                                        struct icmp_echo_hdr *icmp)
{
    errval_t err;
    if (type != ICMP_ER && type != ICMP_ECHO) {
        err = ENET_ERR_ICMP_UNKNOWN_TYPE;
        DEBUG_ERR(err, "unkown ICMP type");
        return err;
    }

    icmp->type = type;
    icmp->code = 0;
    icmp->id = htons(id);
    icmp->seqno = htons(seqno);
    memcpy((char *)icmp + ICMP_HLEN, payload, payload_size);

    icmp->chksum = 0;
    icmp->chksum = inet_checksum(icmp, ICMP_HLEN + payload_size);

    enet_debug_print_icmp_packet(icmp, payload_size);

    return SYS_ERR_OK;
}

static errval_t enet_create_udp_packet(uint16_t udp_src, uint16_t udp_dest, char *payload,
                                       size_t payload_size, struct udp_hdr *udp)
{
    udp->src = htons(udp_src);
    udp->dest = htons(udp_dest);
    udp->len = htons(UDP_HLEN + payload_size);
    memcpy((char *)udp + UDP_HLEN, payload, payload_size);

    udp->chksum = 0;
    // UDP checksum seems to be broken
    // udp->chksum = inet_checksum(udp, UDP_HLEN + payload_size);

    return SYS_ERR_OK;
}

errval_t enet_assemble_arp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                  struct eth_addr eth_dest, ip_addr_t ip_dest,
                                  uint16_t opcode, struct eth_hdr **retarp,
                                  size_t *retarp_size)
{
    errval_t err;

    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(4, "malloc response packet")
    struct eth_hdr *eth = (struct eth_hdr *)malloc(ETH_HLEN + ARP_HLEN);
    ENET_BENCHMARK_STOP(4, "malloc response packet")

    ENET_BENCHMARK_START(4, "create eth packet")
    err = enet_create_eth_packet(eth_src, eth_dest, ETH_TYPE_ARP, eth);
    ENET_BENCHMARK_STOP(4, "create eth packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create ETH packet");
        return err;
    }

    struct arp_hdr *arp = (struct arp_hdr *)((char *)eth + ETH_HLEN);
    ENET_BENCHMARK_START(4, "create arp packet")
    err = enet_create_arp_packet(eth_src, ip_src, eth_dest, ip_dest, opcode, arp);
    ENET_BENCHMARK_STOP(4, "create arp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create ARP packet");
        return err;
    }

    *retarp = eth;
    *retarp_size = ETH_HLEN + ARP_HLEN;

    return SYS_ERR_OK;
}

errval_t enet_assemble_icmp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                   struct eth_addr eth_dest, ip_addr_t ip_dest,
                                   uint8_t type, uint16_t id, uint16_t seqno,
                                   char *payload, size_t payload_size,
                                   struct eth_hdr **reticmp, size_t *reticmp_size)
{
    errval_t err;

    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(4, "malloc response packet")
    struct eth_hdr *eth = (struct eth_hdr *)malloc(ETH_HLEN + IP_HLEN + ICMP_HLEN
                                                   + payload_size);
    ENET_BENCHMARK_STOP(4, "malloc response packet")

    ENET_BENCHMARK_START(4, "create eth packet")
    err = enet_create_eth_packet(eth_src, eth_dest, ETH_TYPE_IP, eth);
    ENET_BENCHMARK_STOP(4, "create eth packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create ETH packet");
        return err;
    }

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    ENET_BENCHMARK_START(4, "create ip packet")
    err = enet_create_ip_packet(eth_src, ip_src, eth_dest, ip_dest, IP_PROTO_ICMP,
                                ICMP_HLEN + payload_size, ip);
    ENET_BENCHMARK_STOP(4, "create ip packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create IP packet");
        return err;
    }

    struct icmp_echo_hdr *icmp = (struct icmp_echo_hdr *)((char *)ip + IP_HLEN);
    ENET_BENCHMARK_START(4, "create icmp packet")
    err = enet_create_icmp_packet(type, id, seqno, payload, payload_size, icmp);
    ENET_BENCHMARK_STOP(4, "create icmp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create ICMP packet");
        return err;
    }


    *reticmp = eth;
    *reticmp_size = ETH_HLEN + IP_HLEN + ICMP_HLEN + payload_size;

    return SYS_ERR_OK;
}

errval_t enet_assemble_udp_packet(struct eth_addr eth_src, ip_addr_t ip_src,
                                  uint16_t udp_src, struct eth_addr eth_dest,
                                  ip_addr_t ip_dest, uint16_t udp_dest, char *payload,
                                  size_t payload_size, struct eth_hdr **retudp,
                                  size_t *retudp_size)
{
    errval_t err;

    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(4, "malloc response packet")
    struct eth_hdr *eth = (struct eth_hdr *)malloc(ETH_HLEN + IP_HLEN + UDP_HLEN
                                                   + payload_size);
    ENET_BENCHMARK_STOP(4, "malloc response packet")

    ENET_BENCHMARK_START(4, "create eth packet")
    err = enet_create_eth_packet(eth_src, eth_dest, ETH_TYPE_IP, eth);
    ENET_BENCHMARK_STOP(4, "create eth packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create ETH packet");
        return err;
    }

    struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + ETH_HLEN);
    ENET_BENCHMARK_START(4, "create ip packet")
    err = enet_create_ip_packet(eth_src, ip_src, eth_dest, ip_dest, IP_PROTO_UDP,
                                UDP_HLEN + payload_size, ip);
    ENET_BENCHMARK_STOP(4, "create ip packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create IP packet");
        return err;
    }

    struct udp_hdr *udp = (struct udp_hdr *)((char *)ip + IP_HLEN);
    ENET_BENCHMARK_START(4, "create udp packet")
    err = enet_create_udp_packet(udp_src, udp_dest, payload, payload_size, udp);
    ENET_BENCHMARK_STOP(4, "create udp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create UDP packet");
        return err;
    }

    *retudp = eth;
    *retudp_size = ETH_HLEN + IP_HLEN + UDP_HLEN + payload_size;

    return SYS_ERR_OK;
}
