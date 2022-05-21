
#include "enet_socket.h"
#include "enet.h"
#include "enet_assembler.h"
#include "enet_safe_queue.h"

static struct udp_socket *enet_get_udp_socket(struct udp_socket *sockets, uint16_t port)
{
    struct udp_socket *s = sockets;
    while (s) {
        if (s->port == port) {
            return s;
        }
        s = s->next;
    }

    return NULL;
}

static void enet_udp_socket_debug_print(struct udp_socket *sockets)
{
    struct udp_socket *s = sockets;

    UDP_DEBUG("========== UDP socket state ======\n");
    while (s) {
        UDP_DEBUG("Port: %d\n", s->port);
        struct udp_socket_buf *buf = s->inbound_head;
        while (buf) {
            UDP_DEBUG("    Packet from %d.%d.%d.%d:%d (%d)\n", (buf->ip >> 24) & 0xFF,
                      (buf->ip >> 16) & 0xFF, (buf->ip >> 8) & 0xFF, buf->ip & 0xFF,
                      buf->port, buf->len);
            buf = buf->next;
        }
        s = s->next;
    }
    UDP_DEBUG("==================================\n");
}

errval_t enet_create_udp_socket(struct enet_driver_state *st, uint16_t port)
{
    if (enet_get_udp_socket(st->udp_sockets, port)) {
        return ENET_ERR_SOCKET_EXISTS;
    }

    struct udp_socket *s = (struct udp_socket *)malloc(sizeof(struct udp_socket));
    if (!s) {
        return LIB_ERR_MALLOC_FAIL;
    }

    s->port = port;
    s->inbound_head = NULL;
    s->inbound_tail = NULL;

    s->next = st->udp_sockets;
    st->udp_sockets = s;

    return SYS_ERR_OK;
}

errval_t enet_destroy_udp_socket(struct enet_driver_state *st, uint16_t port)
{
    if (!st->udp_sockets) {
        return SYS_ERR_OK;
    }

    struct udp_socket *s = st->udp_sockets;
    struct udp_socket *prev_s = NULL;
    while (s) {
        if (s->port == port) {
            break;
        }
        prev_s = s;
        s = s->next;
    }

    struct udp_socket_buf *buf = s->inbound_head;
    struct udp_socket_buf *prev_buf = NULL;
    while (buf) {
        free(buf->data);
        prev_buf = buf;
        buf = buf->next;
        free(prev_buf);
    }

    if (prev_s) {
        prev_s->next = s->next;
    } else {
        // first
        st->udp_sockets = s->next;
    }

    free(s);

    return SYS_ERR_OK;
}

errval_t enet_udp_socket_handle_inbound(struct enet_driver_state *st, ip_addr_t src_ip,
                                        uint16_t src_port, uint16_t dest_port,
                                        char *payload, size_t payload_size)
{
    struct udp_socket *s = enet_get_udp_socket(st->udp_sockets, dest_port);
    if (!s) {
        return ENET_ERR_SOCKET_NOT_FOUND;
    }

    // TODO check type

    struct udp_socket_buf *buf = (struct udp_socket_buf *)malloc(
        sizeof(struct udp_socket_buf));
    if (!buf) {
        return LIB_ERR_MALLOC_FAIL;
    }

    char *buf_data = (char *)malloc(payload_size);
    if (!buf_data) {
        return LIB_ERR_MALLOC_FAIL;
    }

    buf->ip = src_ip;
    buf->port = src_port;
    buf->len = payload_size;
    memcpy(buf_data, payload, payload_size);
    buf->data = buf_data;

    struct udp_socket_buf *last = s->inbound_tail;
    if (last) {
        last->next = buf;
    } else {
        // empty
        s->inbound_head = buf;
    }
    s->inbound_tail = buf;

    enet_udp_socket_debug_print(st->udp_sockets);

    return SYS_ERR_OK;
}

errval_t enet_udp_socket_receive(struct enet_driver_state *st, uint16_t port,
                                 struct udp_socket_buf **retbuf)
{
    struct udp_socket *s = enet_get_udp_socket(st->udp_sockets, port);
    if (!s) {
        return ENET_ERR_SOCKET_NOT_FOUND;
    }

    struct udp_socket_buf *buf = s->inbound_head;
    if (!buf) {
        return ENET_ERR_SOCKET_EMPTY;
    }

    if (s->inbound_tail == s->inbound_head) {
        s->inbound_tail = NULL;
    }
    s->inbound_head = buf->next;

    buf->next = NULL;

    *retbuf = buf;

    return SYS_ERR_OK;
}

errval_t enet_udp_socket_send(struct enet_driver_state *st, uint16_t port_src,
                              ip_addr_t ip_dest, uint16_t port_dest, char *payload,
                              size_t payload_size)
{
    errval_t err;

    if (payload_size >= (1 << 16) - IP_HLEN - UDP_HLEN) {
        return ENET_ERR_UDP_PAYLOAD_SIZE_EXCEEDED;
    }

    struct eth_addr mac_dest;
    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(1, "resolve ip to mac")
    err = enet_get_mac_by_ip(st, ip_dest, &mac_dest);
    ENET_BENCHMARK_STOP(1, "resolve ip to mac")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get MAC for IP");
        return err;
    }

    struct eth_hdr *resp_udp;
    size_t resp_udp_size;
    ENET_BENCHMARK_START(1, "assemble udp packet");
    err = enet_assemble_udp_packet(enet_split_mac(st->mac), ENET_STATIC_IP, port_src,
                                   mac_dest, ip_dest, port_dest, payload, payload_size,
                                   &resp_udp, &resp_udp_size);
    ENET_BENCHMARK_STOP(1, "assemble udp packet");
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble UDP packet");
        return err;
    }

    ENET_BENCHMARK_START(1, "enqueue udp packet")
    err = safe_enqueue(st->safe_txq, (void *)resp_udp, resp_udp_size);
    ENET_BENCHMARK_STOP(1, "enqueue udp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to enqueue buffer");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t enet_create_icmp_socket(struct enet_driver_state *st)
{
    struct icmp_socket *s = (struct icmp_socket *)malloc(sizeof(struct icmp_socket));
    if (!s) {
        return LIB_ERR_MALLOC_FAIL;
    }

    s->inbound_head = NULL;
    s->inbound_tail = NULL;

    st->icmp_socket = s;

    return SYS_ERR_OK;
}

errval_t enet_destroy_icmp_socket(struct enet_driver_state *st)
{
    if (!st->icmp_socket) {
        return SYS_ERR_OK;
    }

    struct icmp_socket_buf *buf = st->icmp_socket->inbound_head;
    struct icmp_socket_buf *prev_buf = NULL;
    while (buf) {
        free(buf->data);
        prev_buf = buf;
        buf = buf->next;
        free(prev_buf);
    }

    free(st->icmp_socket);

    return SYS_ERR_OK;
}

errval_t enet_icmp_socket_handle_inbound(struct enet_driver_state *st, ip_addr_t ip,
                                         uint8_t type, uint16_t id, uint16_t seqno,
                                         char *payload, size_t payload_size)
{
    struct icmp_socket_buf *buf = (struct icmp_socket_buf *)malloc(
        sizeof(struct icmp_socket_buf));
    if (!buf) {
        return LIB_ERR_MALLOC_FAIL;
    }

    char *buf_data = (char *)malloc(payload_size);
    if (!buf_data) {
        return LIB_ERR_MALLOC_FAIL;
    }

    buf->ip = ip;
    buf->id = id;
    buf->seqno = seqno;
    buf->len = payload_size;
    memcpy(buf_data, payload, payload_size);
    buf->data = buf_data;

    struct icmp_socket_buf *last = st->icmp_socket->inbound_tail;
    if (last) {
        last->next = buf;
    } else {
        // empty
        st->icmp_socket->inbound_head = buf;
    }
    st->icmp_socket->inbound_tail = buf;

    return SYS_ERR_OK;
}

errval_t enet_icmp_socket_receive(struct enet_driver_state *st,
                                  struct icmp_socket_buf **retbuf)
{
    struct icmp_socket *s = st->icmp_socket;

    struct icmp_socket_buf *buf = s->inbound_head;
    if (!buf) {
        return ENET_ERR_SOCKET_EMPTY;
    }

    if (s->inbound_tail == s->inbound_head) {
        s->inbound_tail = NULL;
    }
    s->inbound_head = buf->next;

    buf->next = NULL;

    *retbuf = buf;

    return SYS_ERR_OK;
}

errval_t enet_icmp_socket_send(struct enet_driver_state *st, ip_addr_t ip_dest,
                               uint8_t type, uint16_t id, uint16_t seqno, char *payload,
                               size_t payload_size)
{
    errval_t err;

    if (payload_size >= 576 - ICMP_HLEN) {
        return ENET_ERR_ICMP_PAYLOAD_SIZE_EXCEEDED;
    }

    struct eth_addr mac_dest;
    ENET_BENCHMARK_INIT()
    ENET_BENCHMARK_START(1, "resolve ip to mac")
    err = enet_get_mac_by_ip(st, ip_dest, &mac_dest);
    ENET_BENCHMARK_STOP(1, "resolve ip to mac")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get MAC for IP");
        return err;
    }

    struct eth_hdr *resp_icmp;
    size_t resp_icmp_size;
    ENET_BENCHMARK_START(1, "assemble icmp packet")
    err = enet_assemble_icmp_packet(enet_split_mac(st->mac), ENET_STATIC_IP, mac_dest,
                                    ip_dest, type, id, seqno, payload, payload_size,
                                    &resp_icmp, &resp_icmp_size);
    ENET_BENCHMARK_STOP(1, "assemble icmp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble ICMP packet");
        return err;
    }

    ENET_BENCHMARK_START(1, "enqueue icmp packet")
    err = safe_enqueue(st->safe_txq, (void *)resp_icmp, resp_icmp_size);
    ENET_BENCHMARK_STOP(1, "enqueue icmp packet")
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to enqueue buffer");
        return err;
    }
    return SYS_ERR_OK;
}