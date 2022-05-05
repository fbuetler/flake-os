/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_BARRELFISH_AOS_L_MESSAGES_H
#define _LIB_BARRELFISH_AOS_L_MESSAGES_H

#include <aos/aos.h>
#include <aos/aos_rpc_types.h>

#define AOS_LMP_MSG_SIZE(payload_size) (sizeof(struct aos_lmp_msg) + (payload_size))

// forward declaration
struct aos_lmp;
struct aos_lmp_msg;

typedef errval_t (*process_msg_func_t)(struct aos_lmp *);

struct aos_lmp {
    struct thread_mutex lock;
    // TODO(M3): Add state
    struct lmp_chan chan;
    bool is_busy;
    bool use_dynamic_buf;

    struct aos_lmp_msg *recv_msg;
    size_t recv_bytes;
    process_msg_func_t process_msg_func;

    char *buf;
};

struct aos_lmp_msg {
    uint16_t header_bytes;
    uint16_t payload_bytes;
    aos_rpc_msg_type_t message_type;
    struct capref cap;
    char payload[0];
};

enum aos_rpc_channel_type {
    AOS_RPC_BASE_CHANNEL,
    AOS_RPC_MEMORY_CHANNEL,
};

enum aos_rpc_service {
    AOS_RPC_BASE_SERVICE,
    AOS_RPC_MEMORY_SERVICE,
};

void aos_process_number(struct aos_lmp *msg);
void aos_process_string(struct aos_lmp *msg);

/**
 * @brief Initialize an aos_lmp struct from parent to child
 */
errval_t aos_lmp_init_handshake_to_child(struct aos_lmp *init_lmp,
                                         struct aos_lmp *child_lmp,
                                         struct capref recv_cap);
/**
 * \brief Initialize an aos_lmp struct from child to parent.
 */
errval_t aos_lmp_init(struct aos_lmp *lmp, enum aos_rpc_channel_type chan_type);

errval_t aos_lmp_parent_init(struct aos_lmp *lmp);

/**
 * \brief Setup a recv endpoint for rpc
 */
errval_t aos_lmp_set_recv_endpoint(struct aos_lmp *lmp, struct capref *ret_recv_ep_cap);


errval_t aos_lmp_setup_local_chan(struct aos_lmp *lmp, struct capref cap_ep);

/**
 * @brief Helper function to create a message
 */
errval_t aos_lmp_create_msg(struct aos_lmp_msg **ret_msg, aos_rpc_msg_type_t msg_type,
                            size_t payload_size, void *payload, struct capref msg_cap);

errval_t aos_lmp_create_msg_no_pagefault(struct aos_lmp_msg **ret_msg,
                                         aos_rpc_msg_type_t msg_type, size_t payload_size,
                                         void *payload, struct capref msg_cap,
                                         struct aos_lmp_msg *msg);

/**
 * @brief Asynchronously send a message
 */
errval_t aos_lmp_send_msg(struct aos_lmp *lmp, struct aos_lmp_msg *msg);

/**
 * @brief Register a receive handler that should be called on icoming messages
 */
errval_t aos_lmp_register_recv(struct aos_lmp *lmp, process_msg_func_t process_msg_func);

/**
 * @brief Synchronously send a message
 */
errval_t aos_lmp_call(struct aos_lmp *lmp, struct aos_lmp_msg *msg, bool use_dynamic_buf);


#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H