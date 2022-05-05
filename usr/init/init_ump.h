

#ifndef _INIT_INIT_UMP_H_
#define _INIT_INIT_UMP_H_


#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>

// on these channels, we're the client
struct aos_ump aos_ump_client_chans[4];

// on these channels, we're the server
struct aos_ump aos_ump_server_chans[4];
struct thread *aos_ump_server_threads[4];

struct thread *run_ump_listener_thread(struct aos_ump *ump, bool is_malloced);

void aos_ump_receive_listener(struct aos_ump *ump);

int aos_ump_receive_listener_thread_func(void *arg);
int aos_ump_receive_listener_thread_func_malloced(void *arg);


#endif