/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_UMP_H_
#define _INIT_UMP_H_

#include <aos/aos.h>

/*
    memory layout of the URPC frame (BASE_PAGE_SIZE aka 4kb)
    split into two equal sections for send and receive
    every message/metadata section is 64 bytes big

    send queue metadata (mutex = 32)
    send queue (messages)

    recv queue metadata (same as send)
    recv queue (messages)

*/

#define UMP_SHARED_MEM_BYTES BASE_PAGE_SIZE
#define UMP_SECTION_BYTES (UMP_SHARED_MEM_BYTES / 2)

#define UMP_MSG_BYTES 64  // CACHE_LINE_SIZE
#define UMP_MSG_MAX_BYTES (4 * UMP_MSG_BYTES)

#define UMP_METADATA_OFFSET 0
#define UMP_METADATA_BYTES UMP_MSG_BYTES
#define UMP_METADATA_MUTEX_OFFSET 0
#define UMP_METADATA_MUTEX_BYTES (sizeof(struct thread_mutex))

#define UMP_MESSAGES_OFFSET (UMP_METADATA_OFFSET + UMP_METADATA_BYTES)
#define UMP_MESSAGES_BYTES (UMP_SECTION_BYTES - UMP_METADATA_BYTES)

#define UMP_MESSAGES_ENTRIES (UMP_MESSAGES_BYTES / UMP_MSG_BYTES)

enum ump_msg_type {
    UmpPing = 1,
    UmpPong = 2,
    UmpSpawn = 3,
    UmpSendMem = 4,
    UmpSendBootinfo = 5,
};

enum ump_msg_state {
    UmpMessageCreated = 1,
    UmpMessageSent = 2,
    UmpMessageReceived = 3,
};

struct ump_msg_header {
    enum ump_msg_type msg_type;
    enum ump_msg_state msg_state;
    uint8_t len;
    bool last;
};

#define UMP_MSG_HEADER_BYTES (sizeof(struct ump_msg_header))
#define UMP_MSG_PAYLOAD_BYTES (UMP_MSG_BYTES - UMP_MSG_HEADER_BYTES)

struct ump_mem_msg {
    genpaddr_t base;
    gensize_t bytes;
};
struct ump_msg {
    struct ump_msg_header header;
    char payload[UMP_MSG_PAYLOAD_BYTES];
};


struct ump_chan {
    uint64_t *send_base;  // start of the send secion
    uint64_t send_next;   // next send entry
    struct thread_mutex *send_mutex;

    uint64_t *recv_base;  // start of the receive section
    uint64_t recv_next;   // next recv entry
    struct thread_mutex *recv_mutex;
};

void ump_debug_print(struct ump_chan *ump);
errval_t ump_initialize(struct ump_chan *ump, void *shared_mem, bool is_primary);
errval_t ump_send(struct ump_chan *chan, enum ump_msg_type type, char *payload,
                  size_t len);
errval_t ump_receive(struct ump_chan *ump, enum ump_msg_type *rettype, char **retpayload,
                     size_t *retlen);

#endif /* _INIT_UMP_H_ */
