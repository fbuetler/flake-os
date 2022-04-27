

#ifndef _INIT_INIT_UMP_H_
#define _INIT_INIT_UMP_H_


#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/ump_chan.h>

// TODO how do we know how many cores exist in total?
struct ump_chan ump_chans[4];

struct thread *run_ump_listener_thread(void);

void ump_receive_listener(struct ump_chan *chan);

int ump_receive_listener_thread_func(void *arg);


#endif