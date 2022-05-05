

#ifndef _INIT_INIT_RPC_H_
#define _INIT_INIT_RPC_H_

#include <stdio.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>
#include <aos/threads.h>

errval_t init_process_msg(struct aos_lmp *rpc);

void aos_process_ram_cap_request(struct aos_lmp *rpc);
void aos_process_spawn_request(struct aos_lmp *rpc);
errval_t aos_process_serial_write_char(struct aos_lmp *rpc);
errval_t aos_process_serial_read_char_request(struct aos_lmp *rpc);

#endif