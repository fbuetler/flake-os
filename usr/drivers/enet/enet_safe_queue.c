#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <aos/aos.h>
#include <devif/queue_interface.h>
#include <devif/queue_interface_backend.h>

#include "enet.h"
#include "enet_safe_queue.h"


errval_t safe_create(struct safe_q **q, struct enet_queue *other_q)
{
    *q = malloc(sizeof(struct safe_q));
    if (!*q) {
        return LIB_ERR_MALLOC_FAIL;
    }

    (*q)->q = other_q;
    (*q)->free = NULL;

    return SYS_ERR_OK;
}

static errval_t safe_dequeue(struct safe_q *q)
{
    errval_t err;
    struct devq_buf *buf = (struct devq_buf *)malloc(sizeof(struct devq_buf));
    if (!buf) {
        err = LIB_ERR_MALLOC_FAIL;
        return err;
    }

    while (true) {
        err = devq_dequeue(&q->q->q, &buf->rid, &buf->offset, &buf->length,
                           &buf->valid_data, &buf->valid_length, &buf->flags);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to dequeue buffer");
            return err;
        }

        struct safe_free_node *free_node = (struct safe_free_node *)malloc(
            sizeof(struct safe_free_node));
        if (!free_node) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "failed to malloc safe free node");
            return err;
        }

        free_node->buf = buf;
        free_node->next = q->free;
        q->free = free_node;
    }

    return SYS_ERR_OK;
}

static errval_t safe_get_free_buf(struct safe_q *q, struct devq_buf **retbuf)
{
    errval_t err;

    err = safe_dequeue(q);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to dequeue buffer");
        return err;
    }

    if (!q->free) {
        err = ENET_ERR_SAFE_NO_FREE_BUFFER;
        return err;
    }

    struct safe_free_node *free_node = q->free;
    q->free = q->free->next;
    *retbuf = free_node->buf;
    free(free_node);

    return SYS_ERR_OK;
}

errval_t safe_enqueue(struct safe_q *q, safe_region_t *safe_buf)
{
    errval_t err;

    if (safe_buf->length >= SAFE_BUF_SIZE) {
        err = ENET_ERR_SAFE_INVALID_BUFFER_SIZE;
        DEBUG_ERR(err, "buffer size exceeds maximum size");
        return err;
    }

    struct devq_buf *buf;
    err = safe_get_free_buf(q, &buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get free buffer");
        return err;
    }

    struct region_entry *region = enet_get_region(q->q->regions, buf->rid);
    if (!region) {
        err = ENET_ERR_REGION_NOT_FOUND;
        DEBUG_ERR(err, "failed to find region");
        return err;
    }

    lvaddr_t valid_data_base = region->mem.vbase + buf->offset + buf->valid_data;
    memcpy((void *)valid_data_base, safe_buf->data, safe_buf->length);

    return devq_enqueue(&q->q->q, buf->rid, buf->offset, buf->length, buf->valid_data,
                        buf->valid_length, buf->flags);
}
