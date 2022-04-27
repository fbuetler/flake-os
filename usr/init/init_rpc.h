

#ifndef _INIT_INIT_RPC_H_
#define _INIT_INIT_RPC_H_

#include <stdio.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>
#include <aos/threads.h>

// TODO how do we know how many cores exist in total?
struct ump_chan ump_chans[4];

struct thread *run_ump_listener_thread(void);

errval_t init_process_msg(struct aos_rpc *rpc);

errval_t start_process(char *cmd, struct spawninfo *si, domainid_t *pid);
void ump_receive_listener(struct ump_chan *chan);

int ump_receive_listener_thread_func(void *arg);

void aos_process_number(struct aos_rpc_msg *msg);
void aos_process_string(struct aos_rpc_msg *msg);
void aos_process_ram_cap_request(struct aos_rpc *rpc);
void aos_process_spawn_request(struct aos_rpc *rpc);
errval_t aos_process_serial_write_char(struct aos_rpc *rpc);
errval_t aos_process_serial_read_char_request(struct aos_rpc *rpc);

#endif