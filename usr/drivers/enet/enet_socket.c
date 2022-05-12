
#include "enet_socket.h"
#include "enet.h"
#include "enet_assembler.h"
#include "enet_safe_queue.h"

static struct socket *enet_get_socket(struct socket *sockets, uint16_t port)
{
    struct socket *s = sockets;
    while (s) {
        if (s->port == port) {
            return s;
        }
        s = s->next;
    }

    return NULL;
}

static void enet_socket_debug_print(struct socket *sockets)
{
    struct socket *s = sockets;

    UDP_DEBUG("========== socket state ==========\n");
    while (s) {
        UDP_DEBUG("Port: %d\n", s->port);
        struct socket_buf *buf = s->inbound_head;
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

errval_t enet_create_socket(struct enet_driver_state *st, enum socket_proto proto,
                            uint16_t port)
{
    if (enet_get_socket(st->sockets, port)) {
        return ENET_ERR_SOCKET_EXISTS;
    }

    struct socket *s = (struct socket *)malloc(sizeof(struct socket));
    if (!s) {
        return LIB_ERR_MALLOC_FAIL;
    }

    s->proto = proto;
    s->port = port;
    s->inbound_head = NULL;
    s->inbound_tail = NULL;

    s->next = st->sockets;
    st->sockets = s;

    return SYS_ERR_OK;
}

errval_t enet_destroy_socket(struct enet_driver_state *st, uint16_t port)
{
    if (!st->sockets) {
        return SYS_ERR_OK;
    }

    struct socket *s = st->sockets;
    struct socket *prev_s = NULL;
    while (s) {
        if (s->port == port) {
            break;
        }
        prev_s = s;
        s = s->next;
    }

    struct socket_buf *buf = s->inbound_head;
    struct socket_buf *prev_buf = NULL;
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
        st->sockets = s->next;
    }

    free(s);

    return SYS_ERR_OK;
}

errval_t enet_socket_handle_inbound(struct enet_driver_state *st, ip_addr_t src_ip,
                                    uint16_t src_port, uint16_t dest_port, char *payload,
                                    size_t payload_size)
{
    struct socket *s = enet_get_socket(st->sockets, dest_port);
    if (!s) {
        return ENET_ERR_SOCKET_NOT_FOUND;
    }

    // TODO check type

    struct socket_buf *buf = (struct socket_buf *)malloc(sizeof(struct socket_buf));
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

    struct socket_buf *last = s->inbound_tail;
    if (last) {
        last->next = buf;
    } else {
        // empty
        s->inbound_head = buf;
    }
    s->inbound_tail = buf;

    enet_socket_debug_print(st->sockets);

    return SYS_ERR_OK;
}

errval_t enet_socket_receive(struct socket *s, struct socket_buf **retbuf)
{
    struct socket_buf *buf = s->inbound_head;
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

errval_t enet_socket_send(struct enet_driver_state *st, ip_addr_t ip_dest,
                          uint16_t port_dest, char *payload, size_t payload_size)
{
    errval_t err;

    if (payload_size >= (1 << 16) - IP_HLEN - UDP_HLEN) {
        return ENET_ERR_UDP_PAYLOAD_SIZE_EXCEEDED;
    }

    struct eth_addr mac_dest;
    err = enet_get_mac_by_ip(st, ip_dest, &mac_dest);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get MAC for IP");
        return err;
    }

    struct eth_hdr *resp_udp;
    size_t resp_udp_size;
    err = enet_assemble_udp_packet(enet_split_mac(st->mac), ENET_STATIC_IP,
                                   ENET_STATIC_PORT, mac_dest, ip_dest, port_dest,
                                   payload, payload_size, &resp_udp, &resp_udp_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to assemble UDP packet");
        return err;
    }

    err = safe_enqueue(st->safe_txq, (void *)resp_udp, resp_udp_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to enqueue buffer");
        return err;
    }

    return SYS_ERR_OK;
}