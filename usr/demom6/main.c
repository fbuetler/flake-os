/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/deferred.h>
#include <aos/ump_chan.h>

static struct aos_rpc *init_rpc;

int main(int argc, char *argv[])
{
    errval_t err = SYS_ERR_OK;


    init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        USER_PANIC_ERR(err, "init RPC channel NULL?\n");
    }

    printf("this is very very slow\n");

    debug_printf("enter char: ");
    char c;
    err = aos_rpc_serial_getchar(init_rpc, &c);
    debug_printf("\n");

    debug_printf("received char: %c\n", c);

    return 0;



/*
    - bind to any RPC server:  we have on init: base-server, mem-server
        e.g memory server, serial server

*/

    struct ump_chan c_ump;

    coreid_t core_id = 1;
    err = ump_bind(init_rpc, &c_ump, core_id, AOS_RPC_BASE_SERVICE); 
    assert(err_is_ok(err));

    debug_printf("channel is set up!\n");

    
    char p;
    ump_send(&c_ump, UmpPing, &p, 1);
    ump_msg_type rtype;
    char *rpayload;
    size_t rlen;
    err = ump_receive(&c_ump, &rtype, &rpayload, &rlen);
    assert(err_is_ok(err));
    debug_printf("PING: %s\n", rpayload);

    ump_send(&c_ump, UmpClose, &p, 1);
    err = ump_receive(&c_ump, &rtype, &rpayload, &rlen);
    debug_printf("received type: %d\n", rtype);
    assert(err_is_ok(err));

    debug_printf("channel is closed\n");

    //printf("printing char from core 1 to core 0!\n");
    //aos_rpc_serial_putchar(init_rpc, 'x');


    return EXIT_SUCCESS;
}



/*
    aos_rpc
        -> ump
            -> process_msg
        -> lmp
            if same core:
                -> process_msg
            else:
                relay
*/

/*

some process:
    rpc_bind("mem", "serial") -> mem_binding, serial_binding
    rpc_putchar(serial_binding, 'f') -> works
    rpc_putchar(mem_binding, 'w') -> error, wrong server

rpc_bind(endpoint):
    where is endpoint (based on some list of endpoints)
    setup appropriate channel
    create and return binding
*/


/*

DEMO TODO:
    - 

-----------
LMP&UMP unification

struct rpc_chan{
    is_ump: bool
    chan: union{ ump_chan, aos_rpc }
};

rpc_call: chan, msg{
    if chan.is_ump:
        return ump_call
    else:
        return aos_rpc_call
}

- change ump msg types to aos_rpc_msg_type

- bind:
    always creates a UMP channel

- rpc_send:
    if chan.is_ump:
        return ump_send
    else:
        return aos_rpc_send

- rpc_receive:
    if chan.is_ump:
        return ump_receive
    else:
        return aos_rpc_receive_blocking

interface:
    - rpc_bind
    - rpc_send
    - rpc_recv
    - rpc_call  (send & receive)

*/


/*

You should now extend your UMP protocol, to allow all RPC operations to be for-
warded between cores. A sufficient implementation is to route all RPC calls via the
init process (or equivalent), which forwards them on behalf of user-level applica-
tions.

You must be able to reach any RPC server on core 0, from an application on core 1,
and vice versa. You should provide an interface for applications to bind to servers,
and then use this binding to make RPCs.



-------------------------------

init as monitor:
    RPC Services:
        - core 0:
            - base-server
            (- mem-server)
            - serial-driver
        - core 1:
            - base-server

call to bind(core, service):
    create a direct UMP channel to that service

Requirement was: can use rpc service of any core:
    - Design decision: Memory Server can only be accessed from same core
    - serial driver: access over: relayed UMP msg

There shall be no way to register a new service dynamically


*/