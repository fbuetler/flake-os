#include <aos/ump_chan.h>

void ump_debug_print(struct ump_chan *ump)
{
    DEBUG_PRINTF("Send:\nbase: 0x%lx\nnext: %d\n", ump->send_base, ump->send_next);
    DEBUG_PRINTF("SEND MEMORY DUMP:\n");
    for (int i = 0; i < 20; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, ump->send_base - 8 + i,
                     *(ump->send_base - 8 + i));
    }

    DEBUG_PRINTF("Receive:\nbase: 0x%lx\nnext: %d\n", ump->recv_base, ump->recv_next);
    DEBUG_PRINTF("RECEIVE MEMORY DUMP:\n");
    for (int i = 0; i < 20; i++) {
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
    ump->send_mutex = send_mem + UMP_METADATA_MUTEX_OFFSET;
    ump->send_next = 0;
    thread_mutex_init(ump->send_mutex);

    ump->recv_base = recv_mem + UMP_MESSAGES_OFFSET;
    ump->recv_mutex = recv_mem + UMP_METADATA_MUTEX_OFFSET;
    ump->recv_next = 0;
    thread_mutex_init(ump->recv_mutex);

    // DEBUG_PRINTF("Shared memory:\nsend: 0x%lx\nreceive: 0x%lx\n", send_mem, recv_mem);
    // genpaddr_t paddr;
    // paging_vaddr_to_paddr(get_current_paging_state(), (genvaddr_t)ump->send_base,
    // &paddr); DEBUG_PRINTF("Physical frame base: 0x%lx\n", paddr);

    return SYS_ERR_OK;
}

errval_t ump_create_msg(struct ump_msg **retmsg, enum ump_msg_type type, char *payload,
                        size_t len)
{
    struct ump_msg *msg = calloc(UMP_MSG_BYTES, 1);
    msg->msg_state = UmpMessageCreated;

    msg->msg_type = type;
    memcpy(msg->payload, payload, len);

    *retmsg = msg;

    return SYS_ERR_OK;
}

errval_t ump_send(struct ump_chan *ump, struct ump_msg *msg)
{
    errval_t err;
    thread_mutex_lock(ump->send_mutex);

    struct ump_msg *entry = (struct ump_msg *)ump->send_base
                            + ump->send_next * UMP_MESSAGES_BYTES;
    volatile enum ump_msg_state *state = &entry->msg_state;

    if (*state == UmpMessageReceived) {
        err = LIB_ERR_UMP_CHAN_FULL;
        DEBUG_ERR(err, "send queue is full");
        thread_mutex_unlock(ump->send_mutex);
        return err;
    }

    dmb();  // ensure that we checked the above condition before copying

    msg->msg_state = UmpMessageSent;
    memcpy(entry, msg, UMP_MSG_BYTES);
    ump->send_next = (ump->send_next + 1) % UMP_MESSAGES_ENTRIES;

    dmb();  // ensure that the message state is consistent

    // ump_debug_print(ump);

    thread_mutex_unlock(ump->send_mutex);
    return SYS_ERR_OK;
}

errval_t ump_receive(struct ump_chan *ump, struct ump_msg *msg)
{
    // ump_debug_print(ump);

    struct ump_msg *entry = (struct ump_msg *)ump->recv_base
                            + ump->recv_next * UMP_MESSAGES_BYTES;
    volatile enum ump_msg_state *state = &entry->msg_state;

    while (*state != UmpMessageSent) {
        dmb();  // ensure that we checked the above conition before locking and copying
    }

    // ensure that later instructions are only fetched after this point to ensure
    // synchornization with the unlocking of the sending core.
    rdtscp();

    // only lock once the message was actually sent
    thread_mutex_lock(ump->recv_mutex);

    entry->msg_state = UmpMessageReceived;
    memcpy(msg, entry, UMP_MSG_BYTES);
    ump->recv_next = (ump->recv_next + 1) % UMP_MESSAGES_ENTRIES;

    dmb();  // ensure that the message state is consistent

    thread_mutex_unlock(ump->recv_mutex);
    return SYS_ERR_OK;
}