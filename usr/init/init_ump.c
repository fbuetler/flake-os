#include <stdio.h>
#include <stdlib.h>

#include "init_ump.h"

#include "proc_mgmt.h"
#include "init_rpc.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/ump_chan.h>

void ump_receive_listener(struct ump_chan *chan){
    enum ump_msg_type type;
    char *payload;
    size_t len;
    while(1){
        errval_t err = ump_receive(chan, &type, &payload, &len);
        if(err_is_fail(err)){
            assert(!"couldn't receive ump message in receive listener\n");
        }

        switch(type){
            case UmpSpawn:
            {
                char *cmd = payload;
                DEBUG_PRINTF("received ump spawn request for: %s\n", cmd);
                struct spawninfo *info = malloc(sizeof(struct spawninfo));
                domainid_t pid = 0;
                err = start_process(cmd, info, &pid); 
                if(err_is_fail(err)){
                    DEBUG_PRINTF("failed to start process over ump: %s\n", cmd);
                }

                err = ump_send(chan, UmpSpawnResponse, (char *)&pid, sizeof(domainid_t));
                if(err_is_fail(err)){
                    DEBUG_PRINTF("failed to respond to spawn request!\n");
                }

                continue;

            }
            default:
            {
                assert(!"unknown type message received in ump receive listener\n");
                return;
            }
        }

    }
}

int ump_receive_listener_thread_func(void *arg){
    struct ump_chan *chan = (struct ump_chan *)arg; 

    ump_receive_listener(chan);

    return 0;
}

struct thread *run_ump_listener_thread(void){
    struct ump_chan *chan = &ump_chans[0];
    struct thread *t = thread_create(ump_receive_listener_thread_func, (void *)chan);
    return t;
}