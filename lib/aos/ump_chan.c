#include <aos/ump_chan.h>

#include <aos/deferred.h>

void ump_debug_print(struct ump_chan *ump)
{
    size_t show_cache_lines = 32;

    DEBUG_PRINTF("Send - base: 0x%lx - next: %d\n", ump->send_base, ump->send_next);
    for (int i = 0; i < show_cache_lines; i++) {
        char *send_dump = malloc(1 << 8);
        int c = 0;

        sprintf((send_dump + c), "%02d ", i);
        c += 3;

        for (int j = 0; j < 8; j++) {
            sprintf((send_dump + c), "%016lx ", *(ump->send_base + 8 * i + j));
            c += 17;
        }
        DEBUG_PRINTF("%s\n", send_dump);
    }

    DEBUG_PRINTF("Receive - base: 0x%lx - next: %d\n", ump->recv_base, ump->recv_next)
    for (int i = 0; i < show_cache_lines; i++) {
        char *recv_dump = malloc(1 << 8);
        int c = 0;

        sprintf((recv_dump + c), "%02d ", i);
        c += 3;

        for (int j = 0; j < 8; j++) {
            sprintf((recv_dump + c), "%016lx ", *(ump->recv_base + 8 * i + j));
            c += 17;
        }
        DEBUG_PRINTF("%s\n", recv_dump);
    }
}

errval_t ump_initialize(struct ump_chan *ump, void *shared_mem, bool is_primary)
{
    thread_mutex_init(&ump->chan_lock);
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
static void ump_create_msg(struct ump_msg *msg, ump_msg_type type, char *payload,
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
    volatile ump_msg_state *state = &entry->header.msg_state;

    // DEBUG_PRINTF("sending UMP in slot %d\n", ump->send_next);
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

    // no barrier needed as the receiving side has a memory barrier after the check of the
    // message state. This already ensures that the message is not read before the state
    // has been successfully checked

    return SYS_ERR_OK;
}

errval_t ump_send(struct ump_chan *ump, ump_msg_type type, char *payload, size_t len)
{
    errval_t err;
    size_t offset = 0;
    // thread_mutex_lock_nested(&chan->chan_lock);

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

        size_t backoff = 1;
        while (backoff < 1 << 5) {
            err = ump_send_msg(ump, &msg);
            if (err_is_fail(err)) {
                barrelfish_usleep(backoff * 1000);
                backoff <<= 1;
            } else {
                break;
            }
        }
        if (err_is_fail(err)) {
            // thread_mutex_unlock(&ump->chan_lock);
            DEBUG_ERR(err, "Failed to send message");
            return err_push(err, LIB_ERR_UMP_SEND);
        }
    }

    return SYS_ERR_OK;
}

static errval_t ump_receive_msg(struct ump_chan *ump, struct ump_msg *msg)
{
    // ump_debug_print(ump);


    struct ump_msg *entry = (struct ump_msg *)ump->recv_base + ump->recv_next;
    volatile ump_msg_state *state = &entry->header.msg_state;

    // DEBUG_PRINTF("receiving UMP in slot %d\n", ump->recv_next);
    while (*state != UmpMessageSent) {
        // spin, cause it's cheap (L1 ftw!)
    }

    // This barrier does not need to be inside the polling loop as the state enum is
    // volatile. Further, the sending side has a data barrier before setting the correct
    // state. Therefore, the only memory instruction between the barrier on the sending
    // side and the polling loop reading that the state is UmpMessageSent is the sending
    // side writing UmpMessageSent to the cache line.
    dmb();  // ensure that we checked the above condition before copying

    assert(sizeof(struct ump_msg) == UMP_MSG_BYTES);
    memcpy(msg, entry, UMP_MSG_BYTES);

    dmb();  // ensure that the message is received before we mark it logically as received

    entry->header.msg_state = UmpMessageReceived;
    ump->recv_next = (ump->recv_next + 1) % UMP_MESSAGES_ENTRIES;

    // no barrier needed, as the sending side has a memory barrier after its check of the
    // message state


    return SYS_ERR_OK;
}

errval_t ump_receive(struct ump_chan *ump, ump_msg_type *rettype, char **retpayload,
                     size_t *retlen)
{
    // thread_mutex_lock_nested(&ump->chan_lock);
    errval_t err;

    size_t offset = 0;
    char *tmp_payload = malloc(UMP_MSG_MAX_BYTES);

    ump_msg_type msg_type;
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
