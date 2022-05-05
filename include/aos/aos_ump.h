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
#include <aos/aos_lmp.h>

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
#define UMP_MSG_MAX_BYTES (2 * BASE_PAGE_SIZE)

#define UMP_MESSAGES_OFFSET 0
#define UMP_MESSAGES_BYTES UMP_SECTION_BYTES

#define UMP_MESSAGES_ENTRIES (UMP_MESSAGES_BYTES / UMP_MSG_BYTES)

// compresses the aos_rpc_msg_type to a single byte
typedef uint8_t ump_msg_type;

typedef uint8_t ump_msg_state;
static const ump_msg_state UmpMessageCreated = 1;
static const ump_msg_state UmpMessageSent = 2;
static const ump_msg_state UmpMessageReceived = 3;

struct ump_msg_header {
    ump_msg_type msg_type;
    ump_msg_state msg_state;
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

struct aos_ump {
    struct thread_mutex chan_lock;
    uint64_t *send_base;  // start of the send section
    uint64_t send_next;   // next send entry

    uint64_t *recv_base;  // start of the receive section
    uint64_t recv_next;   // next recv entry
};

void aos_ump_debug_print(struct aos_ump *ump);
errval_t aos_ump_initialize(struct aos_ump *ump, void *shared_mem, bool is_primary);
errval_t aos_ump_send(struct aos_ump *chan, aos_rpc_msg_type_t type, char *payload,
                      size_t len);

errval_t aos_ump_receive(struct aos_ump *ump, aos_rpc_msg_type_t *rettype,
                         char **retpayload, size_t *retlen);

errval_t aos_ump_bind(struct aos_lmp *aos_rpc, struct aos_ump *ump, coreid_t core,
                      enum aos_rpc_service service);
errval_t aos_ump_create_chan(struct capref *frame_cap, struct aos_ump *ump,
                             bool alloc_new_frame, bool is_server);

errval_t aos_ump_call(struct aos_ump *ump, aos_rpc_msg_type_t send_type,
                      char *send_payload, size_t send_len, aos_rpc_msg_type_t *recv_type,
                      char **recv_payload, size_t *recv_len);

#endif /* _INIT_UMP_H_ */
