

#ifndef _INIT_INIT_UMP_H_
#define _INIT_INIT_UMP_H_


#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/ump_chan.h>

// on these channels, we're the client
struct ump_chan ump_client_chans[4];

// on these channels, we're the server
struct ump_chan ump_chans[4];

struct thread *run_ump_listener_thread(struct ump_chan *chan, bool is_malloced);

void ump_receive_listener(struct ump_chan *chan);

int ump_receive_listener_thread_func(void *arg);
int ump_receive_listener_thread_func_malloced(void *arg);


#endif