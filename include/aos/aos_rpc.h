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

#ifndef _LIB_BARRELFISH_AOS_MESSAGES_H
#define _LIB_BARRELFISH_AOS_MESSAGES_H

#include <aos/aos.h>


// forward declaration
struct aos_rpc_msg;

typedef errval_t (*process_msg_func_t)(struct aos_rpc *);
/* An RPC binding, which may be transported over LMP or UMP. */
struct aos_rpc {
    // TODO(M3): Add state
    struct lmp_chan chan;
    bool is_busy;

    struct aos_rpc_msg *recv_msg;
    size_t recv_bytes;
    process_msg_func_t process_msg_func;
};

enum aos_rpc_msg_type {
    Handshake = 1,
    SendNumber = 2,
    SendString = 3,
    RamCapRequest = 4,
    RamCapResponse = 5,
    SpawnRequest = 6,
    SpawnResponse = 7,
    SerialWriteChar = 8,
    SerialReadChar = 9,
    SerialReadCharResponse = 10,
    SerialWriteCharResponse = 11,
};

struct aos_rpc_msg {
    uint16_t header_bytes;
    uint16_t payload_bytes;
    enum aos_rpc_msg_type message_type;
    struct capref cap;
    char payload[0];
};

/**
 * @brief Initialize an aos_rpc struct from parent to child
 */
errval_t aos_rpc_init_chan_to_child(struct aos_rpc *init_rpc, struct aos_rpc *child_rpc);
/**
 * \brief Initialize an aos_rpc struct from child to parent.
 */
errval_t aos_rpc_init(struct aos_rpc *rpc);

/**
 * @brief Helper function to create a message
 */
errval_t aos_rpc_create_msg(struct aos_rpc_msg **ret_msg, enum aos_rpc_msg_type msg_type,
                            size_t payload_size, void *payload, struct capref msg_cap);

errval_t aos_rpc_create_msg_no_pagefault(struct aos_rpc_msg **ret_msg, enum aos_rpc_msg_type msg_type, size_t payload_size, void *payload, struct capref msg_cap, struct aos_rpc_msg *msg);

/**
 * @brief Asynchronously send a message
 */
errval_t aos_rpc_send_msg(struct aos_rpc *rpc, struct aos_rpc_msg *msg);

/**
 * @brief Register a receive handler that should be called on icoming messages
 */
errval_t aos_rpc_register_recv(struct aos_rpc *rpc, process_msg_func_t process_msg_func);

/**
 * @brief Synchronously send a message
 */
errval_t aos_rpc_call(struct aos_rpc *rpc, struct aos_rpc_msg *msg);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *chan, const char *string);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *chan, size_t bytes, size_t alignment,
                             struct capref *retcap, size_t *ret_bytes);


/**
 * \brief Get one character from the serial port
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *chan, char *retc);


/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *chan, char c);

/**
 * \brief Request that the process manager start a new process
 * \arg cmdline the name of the process that needs to be spawned (without a
 *           path prefix) and optionally any arguments to pass to it
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *cmdline, coreid_t core,
                               domainid_t *newpid);

/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct aos_rpc *chan, domainid_t pid, char **name);

/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *chan, domainid_t **pids,
                                      size_t *pid_count);

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void);

#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H