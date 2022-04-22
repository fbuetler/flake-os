/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_ICC_H_
#define _INIT_ICC_H_

#include <aos/aos.h>

/*
    memory layout of the URPC frame (BASE_PAGE_SIZE aka 4kb)
    split into two equal sections for send and receive
    every message/metadata section is 64 bytes big

    send queue metadata (mutex + producer + consumer = 32 + 8 + 8 = 48)
    send queue (messages)

    recv queue metadata (same as send)
    recv queue (messages)

*/

#define ICC_SHARED_MEM_BYTES BASE_PAGE_SIZE
#define ICC_SECTION_BYTES (ICC_SHARED_MEM_BYTES / 2)

#define ICC_MSG_BYTES 64  // CACHE_LINE_SIZE

#define ICC_METADATA_OFFSET 0
#define ICC_METADATA_BYTES ICC_MSG_BYTES
#define ICC_METADATA_MUTEX_OFFSET 0
#define ICC_METADATA_MUTEX_BYTES (sizeof(struct thread_mutex))

#define ICC_MESSAGES_OFFSET (ICC_METADATA_OFFSET + ICC_METADATA_BYTES)
#define ICC_MESSAGES_BYTES (ICC_SECTION_BYTES - ICC_METADATA_BYTES)

#define ICC_MESSAGES_ENTRIES (ICC_MESSAGES_BYTES / ICC_MSG_BYTES)

enum icc_msg_type {
    IccSpawnRequest = 1,
    IccSpawnResponse = 2,
};

enum icc_msg_state {
    MessageCreated = 1,
    MessageSent = 2,
    MessageReceived = 3,
};

struct icc_msg {
    enum icc_msg_type msg_type;
    enum icc_msg_state msg_state;
    char payload[];
};

#define ICC_MSG_HEADER_BYTES (sizeof(struct icc_msg))
#define ICC_MSG_PAYLOAD_BYTES (ICC_MSG_BYTES - ICC_MSG_HEADER_BYTES)

struct icc {
    uint64_t *send_base;  // start of the send secion
    uint64_t send_next;   // next send entry
    struct thread_mutex *send_mutex;

    uint64_t *recv_base;  // start of the receive section
    uint64_t recv_next;   // next recv entry
    struct thread_mutex *recv_mutex;
};

void icc_debug_print(struct icc *icc);
errval_t icc_initialize(struct icc *icc, void *send_mem, void *recv_mem);
errval_t icc_create_msg(struct icc_msg **retmsg, enum icc_msg_type type, char *payload,
                        size_t len);
errval_t icc_send(struct icc *icc, struct icc_msg *msg);
errval_t icc_receive(struct icc *icc, struct icc_msg *msg);

#endif /* _INIT_ICC_H_ */
