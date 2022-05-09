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
#include <drivers/sdhc.h>

static struct aos_rpc *init_rpc;

#define SDHC2_BASE 0x5B020000
#define SDHC2_SIZE (0x5B02FFFF - SDHC2_BASE + 1)

int main(int argc, char *argv[])
{
    errval_t err = SYS_ERR_OK;

    init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        USER_PANIC_ERR(err, "init RPC channel NULL?\n");
    }

    // need to map sdhc2 base for the sdcard driver



    DEBUG_PRINTF("done here\n");
    return EXIT_SUCCESS;
}
