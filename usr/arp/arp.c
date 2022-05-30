/**
 * \file
 * \brief Ping application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_network.h>

int main(int argc, char *argv[])
{
    errval_t err;

    char *msg;
    size_t msg_size;
    err = aos_arp_table_get(&msg, &msg_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get ARP table");
        return err;
    }

    debug_printf("%s", msg);

    return EXIT_SUCCESS;
}
