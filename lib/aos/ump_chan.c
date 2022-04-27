#include <aos/ump_chan.h>

void ump_debug_print(struct ump_chan *ump)
{
    DEBUG_PRINTF("Send:\nbase: 0x%lx\nnext: %d\n", ump->send_base, ump->send_next);
    DEBUG_PRINTF("SEND MEMORY DUMP:\n");
    size_t show_cache_lines = 3;
    for (int i = 0; i < show_cache_lines * 8; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, ump->send_base - 8 + i,
                     *(ump->send_base - 8 + i));
    }

    DEBUG_PRINTF("Receive:\nbase: 0x%lx\nnext: %d\n", ump->recv_base, ump->recv_next);
    DEBUG_PRINTF("RECEIVE MEMORY DUMP:\n");
    for (int i = 0; i < show_cache_lines * 8; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, ump->recv_base - 8 + i,
                     *(ump->recv_base - 8 + i));
    }
}

errval_t ump_initialize(struct ump_chan *ump, void *shared_mem, bool is_primary)
{
    void *send_mem;
    void *recv_mem;
    if (is_primary) {
        send_mem = shared_mem;
        recv_mem = shared_mem + UMP_SECTION_BYTES;
    } else {
        send_mem = shared_mem + UMP_SECTION_BYTES;
        recv_mem = shared_mem;
    }

    ump->send_base = send_mem + UMP_MESSAGES_OFFSET;
    ump->send_next = 0;

    ump->recv_base = recv_mem + UMP_MESSAGES_OFFSET;
    ump->recv_next = 0;

    // DEBUG_PRINTF("Shared memory:\nsend: 0x%lx\nreceive: 0x%lx\n", send_mem, recv_mem);
    // genpaddr_t paddr;
    // paging_vaddr_to_paddr(get_current_paging_state(), (genvaddr_t)ump->send_base,
    // &paddr); DEBUG_PRINTF("Physical frame base: 0x%lx\n", paddr);

    return SYS_ERR_OK;
}

/**
 * Populate ump_msg struct on the stack
 */
static void ump_create_msg(struct ump_msg *msg, enum ump_msg_type type, char *payload,
                           size_t len, bool is_last)
{
    msg->header.msg_state = UmpMessageCreated;
    msg->header.msg_type = type;
    msg->header.last = is_last;
    msg->header.len = len;
    memcpy(msg->payload, payload, len);
}

static errval_t ump_send_msg(struct ump_chan *ump, struct ump_msg *msg)
{
    errval_t err;

    struct ump_msg *entry = (struct ump_msg *)ump->send_base + ump->send_next;
    volatile enum ump_msg_state *state = &entry->header.msg_state;

    if (*state == UmpMessageSent) {
        err = LIB_ERR_UMP_CHAN_FULL;
        DEBUG_ERR(err, "send queue is full");
        return err;
    }

    dmb();  // ensure that we checked the above condition before copying

    memcpy(entry, msg, UMP_MSG_BYTES);

    dmb();  // ensure that the message is written to memory before logically mark it as sent

    entry->header.msg_state = UmpMessageSent;
    ump->send_next = (ump->send_next + 1) % UMP_MESSAGES_ENTRIES;

    dmb();  // ensure that the message state is consistent

    rdtscp();  // barrier spam

    return SYS_ERR_OK;
}

errval_t ump_send(struct ump_chan *chan, enum ump_msg_type type, char *payload, size_t len)
{
    errval_t err;
    size_t offset = 0;

    if (len > UMP_MSG_MAX_BYTES) {
        err = LIB_ERR_UMP_SEND;
        DEBUG_ERR(err, "Message size exceeded max allowed size");
        return err;
    }

    struct ump_msg msg;
    while (offset < len) {
        size_t current_payload_len = MIN(len - offset, UMP_MSG_PAYLOAD_BYTES);
        size_t current_offset = offset;
        offset += current_payload_len;

        ump_create_msg(&msg, type, payload + current_offset, current_payload_len,
                       offset >= len);

        err = ump_send_msg(chan, &msg);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to send message");
            err = err_push(err, LIB_ERR_UMP_SEND);
            return err;
        }
    }

    return SYS_ERR_OK;
}

static errval_t ump_receive_msg(struct ump_chan *ump, struct ump_msg *msg)
{
    // ump_debug_print(ump);

    struct ump_msg *entry = (struct ump_msg *)ump->recv_base + ump->recv_next;
    volatile enum ump_msg_state *state = &entry->header.msg_state;

    while (*state != UmpMessageSent) {
        dmb();  // ensure that we checked the above condition before copying and every check
    }

    // ensure that later instructions are only fetched after this point to ensure
    // synchornization with the unlocking of the sending core.
    rdtscp();

    assert(sizeof(struct ump_msg) == UMP_MSG_BYTES);
    memcpy(msg, entry, UMP_MSG_BYTES);

    dmb();  // ensure that the message is received before we mark it logically as received

    entry->header.msg_state = UmpMessageReceived;
    ump->recv_next = (ump->recv_next + 1) % UMP_MESSAGES_ENTRIES;

    dmb();  // ensure that the message state is consistent

    return SYS_ERR_OK;
}

errval_t ump_receive(struct ump_chan *ump, enum ump_msg_type *rettype, char **retpayload,
                     size_t *retlen)
{
    errval_t err;

    size_t offset = 0;
    char *tmp_payload = malloc(UMP_MSG_MAX_BYTES);

    enum ump_msg_type msg_type;
    bool is_last = false;
    while (!is_last) {
        struct ump_msg msg;
        err = ump_receive_msg(ump, &msg);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to receive message");
            return err_push(err, LIB_ERR_UMP_RECV);
        }

        memcpy(tmp_payload + offset, &msg.payload, msg.header.len);

        offset += msg.header.len;
        is_last = msg.header.last;
        msg_type = msg.header.msg_type;
    }

    char *payload = malloc(offset);
    memcpy(payload, tmp_payload, offset);
    free(tmp_payload);

    *rettype = msg_type;
    *retpayload = payload;
    *retlen = offset;

    return SYS_ERR_OK;
}
