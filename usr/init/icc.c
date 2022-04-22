#include "icc.h"

void icc_debug_print(struct icc *icc)
{
    DEBUG_PRINTF("Send:\nbase: 0x%lx\nnext: %d\n", icc->send_base, icc->send_next);
    DEBUG_PRINTF("SEND MEMORY DUMP:\n");
    for (int i = 0; i < 20; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, icc->send_base - 8 + i,
                     *(icc->send_base - 8 + i));
    }

    DEBUG_PRINTF("Receive:\nbase: 0x%lx\nnext: %d\n", icc->recv_base, icc->recv_next);
    DEBUG_PRINTF("RECEIVE MEMORY DUMP:\n");
    for (int i = 0; i < 20; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, icc->recv_base - 8 + i,
                     *(icc->recv_base - 8 + i));
    }
}

errval_t icc_initialize(struct icc *icc, void *send_mem, void *recv_mem)
{
    icc->send_base = send_mem + ICC_MESSAGES_OFFSET;
    icc->send_mutex = send_mem + ICC_METADATA_MUTEX_OFFSET;
    icc->send_next = 0;
    thread_mutex_init(icc->send_mutex);

    icc->recv_base = recv_mem + ICC_MESSAGES_OFFSET;
    icc->recv_mutex = recv_mem + ICC_METADATA_MUTEX_OFFSET;
    icc->recv_next = 0;
    thread_mutex_init(icc->recv_mutex);

    // DEBUG_PRINTF("Shared memory:\nsend: 0x%lx\nreceive: 0x%lx\n", send_mem, recv_mem);
    // genpaddr_t paddr;
    // paging_vaddr_to_paddr(get_current_paging_state(), (genvaddr_t)icc->send_base,
    // &paddr); DEBUG_PRINTF("Physical frame base: 0x%lx\n", paddr);

    return SYS_ERR_OK;
}

errval_t icc_create_msg(struct icc_msg **retmsg, enum icc_msg_type type, char *payload,
                        size_t len)
{
    struct icc_msg *msg = calloc(ICC_MSG_BYTES, 1);
    msg->msg_state = MessageCreated;

    msg->msg_type = type;
    memcpy(msg->payload, payload, len);

    *retmsg = msg;

    return SYS_ERR_OK;
}

errval_t icc_send(struct icc *icc, struct icc_msg *msg)
{
    errval_t err;
    thread_mutex_lock(icc->send_mutex);

    struct icc_msg *entry = (struct icc_msg *)icc->send_base
                            + icc->send_next * ICC_MESSAGES_BYTES;
    volatile enum icc_msg_state *state = &entry->msg_state;

    if (*state == MessageReceived) {
        err = LIB_ERR_UMP_CHAN_FULL;
        DEBUG_ERR(err, "send queue is full");
        thread_mutex_unlock(icc->send_mutex);
        return err;
    }

    dmb();  // ensure that we checked the above condition before copying

    msg->msg_state = MessageSent;
    memcpy(entry, msg, ICC_MSG_BYTES);
    icc->send_next = (icc->send_next + 1) % ICC_MESSAGES_ENTRIES;

    dmb();  // ensure that the message state is consistent

    // icc_debug_print(icc);

    thread_mutex_unlock(icc->send_mutex);
    return SYS_ERR_OK;
}

errval_t icc_receive(struct icc *icc, struct icc_msg *msg)
{
    errval_t err;
    thread_mutex_lock(icc->recv_mutex);

    // icc_debug_print(icc);

    struct icc_msg *entry = (struct icc_msg *)icc->recv_base
                            + icc->recv_next * ICC_MESSAGES_BYTES;
    volatile enum icc_msg_state *state = &entry->msg_state;

    if (*state != MessageSent) {
        err = LIB_ERR_UMP_BUFSIZE_INVALID;
        DEBUG_ERR(err, "recv queue is empty");
        thread_mutex_unlock(icc->recv_mutex);
        return err;
    }

    dmb();  // ensure that we checked the above conition before copying

    memcpy(msg, entry, ICC_MSG_BYTES);
    icc->recv_next = (icc->recv_next + 1) % ICC_MESSAGES_ENTRIES;

    dmb();  // ensure that the message state is consistent

    thread_mutex_unlock(icc->recv_mutex);
    return SYS_ERR_OK;
}