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

#define AOS_RPC_MSG_SIZE(payload_size) (sizeof(struct aos_rpc_msg) + (payload_size))

// forward declaration
struct aos_rpc_msg;

typedef errval_t (*process_msg_func_t)(struct aos_lmp *);
/* An RPC binding, which may be transported over LMP or UMP. */
struct aos_lmp {
    struct thread_mutex lock;
    // TODO(M3): Add state
    struct lmp_chan chan;
    bool is_busy;
    bool use_dynamic_buf;

    struct aos_rpc_msg *recv_msg;
    size_t recv_bytes;
    process_msg_func_t process_msg_func;

    char *buf;
};

typedef enum aos_rpc_msg_type {
    AosRpcHandshake = 1,
    AosRpcSendNumber,
    AosRpcSendNumberResponse,
    AosRpcSendString,
    AosRpcSendStringResponse,
    AosRpcRamCapRequest,
    AosRpcRamCapResponse,
    AosRpcSpawnRequest,
    AosRpcSpawnResponse,
    AosRpcSerialWriteChar,
    AosRpcSerialReadChar,
    AosRpcSerialReadCharResponse,
    AosRpcSerialWriteCharResponse,
    AosRpcPid2Name,
    AosRpcPid2NameResponse,
    AosRpcGetAllPids,
    AosRpcGetAllPidsResponse,
    AosRpcUmpBindRequest,
    AosRpcUmpBindResponse,
    AosRpcPing,
    AosRpcPong,
    AosRpcClose,
    AosRpcCloseReponse,
    AosRpcCpuOff,
    AosRpcBind,
    AosRpcBindReponse,
    AosRpcSendBootinfo,
    AosRpcSendMMStrings
} aos_rpc_msg_type_t;

struct aos_rpc_msg {
    uint16_t header_bytes;
    uint16_t payload_bytes;
    aos_rpc_msg_type_t message_type;
    struct capref cap;
    char payload[0];
};

enum aos_rpc_channel_type{
    AOS_RPC_BASE_CHANNEL,
    AOS_RPC_MEMORY_CHANNEL,
};

enum aos_rpc_service{
    AOS_RPC_BASE_SERVICE,
    AOS_RPC_MEMORY_SERVICE,
};

void aos_process_number(struct aos_lmp *msg);
void aos_process_string(struct aos_lmp *msg);

/**
 * @brief Initialize an aos_lmp struct from parent to child
 */
errval_t aos_lmp_init_handshake_to_child(struct aos_lmp *init_lmp, struct aos_lmp *child_lmp, struct capref recv_cap);
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
errval_t aos_rpc_create_msg(struct aos_rpc_msg **ret_msg, enum aos_rpc_msg_type msg_type,
                            size_t payload_size, void *payload, struct capref msg_cap);

errval_t aos_rpc_create_msg_no_pagefault(struct aos_rpc_msg **ret_msg, enum aos_rpc_msg_type msg_type, size_t payload_size, void *payload, struct capref msg_cap, struct aos_rpc_msg *msg);

/**
 * @brief Asynchronously send a message
 */
errval_t aos_lmp_send_msg(struct aos_lmp *lmp, struct aos_rpc_msg *msg);

/**
 * @brief Register a receive handler that should be called on icoming messages
 */
errval_t aos_lmp_register_recv(struct aos_lmp *lmp, process_msg_func_t process_msg_func);

/**
 * @brief Synchronously send a message
 */
errval_t aos_lmp_call(struct aos_lmp *lmp, struct aos_rpc_msg *msg, bool use_dynamic_buf);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct rpc *chan, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct rpc *rpc, const char *string);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct rpc *chan, size_t bytes, size_t alignment,
                             struct capref *retcap, size_t *ret_bytes);


/**
 * \brief Get one character from the serial port
 */
errval_t aos_rpc_serial_getchar(struct rpc *chan, char *retc);


/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_serial_putchar(struct rpc *chan, char c);

/**
 * \brief Request that the process manager start a new process
 * \arg cmdline the name of the process that needs to be spawned (without a
 *           path prefix) and optionally any arguments to pass to it
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct rpc *chan, char *cmdline, coreid_t core,
                               domainid_t *newpid);

/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct rpc *rpc, domainid_t pid, char **name);

/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct rpc *rpc, domainid_t **pids,
                                      size_t *pid_count);

/**
 * \brief Returns the RPC channel to init.
 */
struct rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct rpc *aos_rpc_get_serial_channel(void);

#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H