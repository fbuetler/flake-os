#include "icc.h"

errval_t icc_initialize(struct icc *icc, void *send_mem, void *recv_mem)
{
    debug_printf("initializing icc\n");

    icc->send_base = send_mem + ICC_MESSAGES_OFFSET;
    icc->send_mutex = send_mem + ICC_METADATA_MUTEX_OFFSET;
    icc->send_head = send_mem + ICC_METADATA_PRODUCER_OFFSET;
    icc->send_tail = send_mem + ICC_METADATA_CONSUMER_OFFSET;

    icc->recv_base = send_mem + ICC_MESSAGES_OFFSET;
    icc->recv_mutex = send_mem + ICC_METADATA_MUTEX_OFFSET;
    icc->recv_head = send_mem + ICC_METADATA_CONSUMER_OFFSET;
    icc->recv_tail = send_mem + ICC_METADATA_PRODUCER_OFFSET;

    debug_printf("initialized icc\n");

    return SYS_ERR_OK;
}

errval_t icc_send(struct icc *icc, struct icc_msg *msg)
{
    errval_t err;

    debug_printf("sending message\n");

    if (sizeof(msg) != ICC_MSG_BYTES) {
        err = LIB_ERR_UMP_BUFSIZE_INVALID;
        debug_printf("size: %ld\n", sizeof(msg));
        DEBUG_ERR(err, "msg is of an invalid size");
        return err;
    }

    if (*icc->recv_head == *icc->recv_tail) {
        err = LIB_ERR_UMP_CHAN_FULL;
        DEBUG_ERR(err, "send queue is full");
        return err;
    }

    memcpy(*icc->send_head, msg, ICC_MSG_BYTES);

    *icc->send_head = ICC_NEXT(icc->send_base, *icc->send_head);

    debug_printf("sent message\n");

    return SYS_ERR_OK;
}

errval_t icc_receive(struct icc *icc, struct icc_msg *msg)
{
    errval_t err;

    debug_printf("receiving message\n");

    if (*icc->recv_head == *icc->recv_tail) {
        err = LIB_ERR_UMP_BUFSIZE_INVALID;
        DEBUG_ERR(err, "recv queue is empty");
        return err;
    }

    memcpy(msg, *icc->recv_tail, ICC_MSG_BYTES);

    *icc->recv_tail = ICC_NEXT(icc->recv_base, *icc->recv_tail);

    debug_printf("received message\n");

    return SYS_ERR_OK;
}