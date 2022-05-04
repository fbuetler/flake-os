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

    DEBUG_PRINTF("demom6 started....\n");

    init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        USER_PANIC_ERR(err, "init RPC channel NULL?\n");
    }

    struct ump_chan c_ump;

    err = ump_bind(init_rpc, &c_ump, 0, AOS_RPC_BASE_SERVICE); 
    assert(err_is_ok(err));

    char p = 'p';
    ump_send(&c_ump, UmpClose, &p, 1);


    ump_msg_type rtype;
    char *rpayload;
    size_t rlen;
    err = ump_receive(&c_ump, &rtype, &rpayload, &rlen);
    debug_printf("received type: %d\n", rtype);
    assert(err_is_ok(err));

    printf("channel is set up!\n");

    //printf("printing char from core 1 to core 0!\n");
    //aos_rpc_serial_putchar(init_rpc, 'x');

    return EXIT_SUCCESS;
}