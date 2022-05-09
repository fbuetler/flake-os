/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */
#ifndef ENET_SAFE_H_
#define ENET_SAFE_H_ 1

#include <aos/aos.h>
#include <devif/queue_interface.h>

#define SAFE_BUF_SIZE 2048

typedef struct {
    char *data[SAFE_BUF_SIZE];
    size_t length;
} safe_region_t;

struct safe_free_node {
    struct devq_buf *buf;
    struct safe_free_node *next;
};

// keeps track which buffers are currently owned by the device and
// which buffers are still owned by the process
struct safe_q {
    struct enet_queue *q;
    struct safe_free_node *free;
};

errval_t safe_create(struct safe_q **q, struct enet_queue *other_q);
errval_t safe_enqueue(struct safe_q *q, safe_region_t *region);

#endif /* ENET_SAFE_H_ */
