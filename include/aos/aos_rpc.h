#ifndef _INIT_AOS_RPC_H
#define _INIT_AOS_RPC_H

#include <aos/aos_rpc_types.h>
#include <aos/aos_lmp.h>
#include <aos/aos_ump.h>

struct aos_rpc {
    union {
        struct aos_lmp lmp;
        struct aos_ump ump;
    } u;
    bool is_lmp;
};

void aos_rpc_init_from_ump(struct aos_rpc *rpc, struct aos_ump *chan);
void aos_rpc_init_from_lmp(struct aos_rpc *rpc, struct aos_lmp *chan);

errval_t aos_rpc_call(struct aos_rpc *rpc, struct aos_rpc_msg msg,
                      struct aos_rpc_msg *retmsg);

errval_t aos_rpc_bind(struct aos_rpc *init_lmp, struct aos_rpc *rpc, coreid_t core,
                      enum aos_rpc_service service);
errval_t aos_rpc_send_errval(struct aos_rpc *rpc, errval_t err_send);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string);

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

errval_t aos_rpc_kill_process(struct aos_rpc *rpc, const domainid_t *pid);

/**
 * \brief Handles a request from a client bound to the server
 *
 * \arg request aos_rpc_msg containing a nameservice_rpc_msg that contains the handler and
 * other things to properly handle the request \arg response the response message created
 * by the handler
 */
void aos_rpc_process_client_request(struct aos_rpc_msg *request,
                                    struct aos_rpc_msg *response);

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
errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name);

/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
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



#endif