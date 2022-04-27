

#ifndef _INIT_INIT_RPC_H_
#define _INIT_INIT_RPC_H_

#include <stdio.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>
#include <aos/threads.h>

errval_t init_process_msg(struct aos_rpc *rpc);

void aos_process_number(struct aos_rpc_msg *msg);
void aos_process_string(struct aos_rpc_msg *msg);
void aos_process_ram_cap_request(struct aos_rpc *rpc);
void aos_process_spawn_request(struct aos_rpc *rpc);
errval_t aos_process_serial_write_char(struct aos_rpc *rpc);
errval_t aos_process_serial_read_char_request(struct aos_rpc *rpc);

#endif