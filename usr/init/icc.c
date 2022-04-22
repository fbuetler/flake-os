#include "icc.h"

errval_t icc_initialize(struct icc *icc, void *send_mem, void *recv_mem)
{
    icc->send_base = send_mem + ICC_MESSAGES_OFFSET;
    icc->send_mutex = send_mem + ICC_METADATA_MUTEX_OFFSET;
    icc->send_head = send_mem + ICC_METADATA_PRODUCER_OFFSET;
    icc->send_tail = send_mem + ICC_METADATA_CONSUMER_OFFSET;
    *icc->send_head = icc->send_base;
    *icc->send_tail = icc->send_base;
    thread_mutex_init(icc->send_mutex);

    icc->recv_base = recv_mem + ICC_MESSAGES_OFFSET;
    icc->recv_mutex = recv_mem + ICC_METADATA_MUTEX_OFFSET;
    icc->recv_head = recv_mem + ICC_METADATA_PRODUCER_OFFSET;
    icc->recv_tail = recv_mem + ICC_METADATA_CONSUMER_OFFSET;
    *icc->recv_head = icc->recv_base;
    *icc->recv_tail = icc->recv_base;
    thread_mutex_init(icc->recv_mutex);

    DEBUG_PRINTF("Shared memory:\nsend: 0x%lx\nreceive: 0x%lx\n", send_mem, recv_mem);

    DEBUG_PRINTF("Send:\nbase: 0x%lx\nhead: 0x%lx -> 0x%lx\ntail: 0x%lx -> "
                 "0x%lx\n",
                 icc->send_base, icc->send_head, *icc->send_head, icc->send_tail,
                 *icc->send_tail);

    DEBUG_PRINTF("Receive:\nbase: 0x%lx\nhead: 0x%lx -> 0x%lx\ntail: 0x%lx -> "
                 "0x%lx\n",
                 icc->recv_base, icc->recv_head, *icc->recv_head, icc->recv_tail,
                 *icc->recv_tail);

    genpaddr_t paddr;
    paging_vaddr_to_paddr(get_current_paging_state(), (genvaddr_t)icc->send_base, &paddr);
    DEBUG_PRINTF("Physical frame base: 0x%lx\n", paddr);

    return SYS_ERR_OK;
}

errval_t icc_send(struct icc *icc, struct icc_msg *msg)
{
    errval_t err;

    thread_mutex_lock(icc->send_mutex);
    DEBUG_PRINTF("sending message\n");

    if (msg->header_bytes + msg->payload_bytes != ICC_MSG_BYTES) {
        err = LIB_ERR_UMP_BUFSIZE_INVALID;
        debug_printf("size: %ld\n", msg->header_bytes + msg->payload_bytes);
        DEBUG_ERR(err, "msg is of an invalid size");
        thread_mutex_unlock(icc->send_mutex);
        return err;
    }

    if (*(icc->recv_head + sizeof(uint64_t)) == *icc->recv_tail) {
        err = LIB_ERR_UMP_CHAN_FULL;
        DEBUG_ERR(err, "send queue is full");
        thread_mutex_unlock(icc->send_mutex);
        return err;
    }

    dmb();
    memcpy(*icc->send_head, msg, ICC_MSG_BYTES);
    dmb();
    *icc->send_head = ICC_NEXT(icc->send_base, *icc->send_head);
    dmb();

    DEBUG_PRINTF("Send mutex: 0x%lx\nProduced: [0x%lx, 0x%lx]\nConsumed: [0x%lx, "
                 "0x%lx]\n",
                 icc->send_mutex, icc->send_head, *icc->send_head, icc->send_tail,
                 *icc->send_tail);

    DEBUG_PRINTF("SEND MEMORY DUMP:\n");
    for (int i = 0; i < 20; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, icc->send_base - 8 + i,
                     *(icc->send_base - 8 + i));
    }

    DEBUG_PRINTF("sent message\n");
    thread_mutex_unlock(icc->send_mutex);

    return SYS_ERR_OK;
}

errval_t icc_receive(struct icc *icc, struct icc_msg *msg)
{
    errval_t err;

    thread_mutex_lock(icc->recv_mutex);
    DEBUG_PRINTF("receiving message\n");

    // TODO *icc->recv_head is probably read from cache
    DEBUG_PRINTF("Receive mutex: 0x%lx\nProduced: [0x%lx, 0x%lx]\nConsumed: [0x%lx, "
                 "0x%lx]\n",
                 icc->recv_mutex, icc->recv_head, *icc->recv_head, icc->recv_tail,
                 *icc->recv_tail);
    DEBUG_PRINTF("%s\n", icc->recv_base + 1);
    DEBUG_PRINTF("[0x%lx, 0x%lx]\n", icc->recv_base - 4, *(icc->recv_base - 4));

    DEBUG_PRINTF("RECEIVE MEMORY DUMP:\n");
    for (int i = 0; i < 20; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, icc->recv_base - 8 + i,
                     *(icc->recv_base - 8 + i));
    }

    if (*icc->recv_head == *icc->recv_tail) {
        err = LIB_ERR_UMP_BUFSIZE_INVALID;
        DEBUG_ERR(err, "recv queue is empty");
        thread_mutex_unlock(icc->recv_mutex);
        return err;
    }

    dmb();
    memcpy(msg, *icc->recv_tail, ICC_MSG_BYTES);
    dmb();
    *icc->recv_tail = ICC_NEXT(icc->recv_base, *icc->recv_tail);
    dmb();

    DEBUG_PRINTF("received message\n");
    thread_mutex_unlock(icc->recv_mutex);

    return SYS_ERR_OK;
}