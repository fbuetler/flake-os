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
#include <ctype.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/deferred.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/cache.h>
#include <fs/fat32.h>
#include <fs/fs.h>

int main(int argc, char *argv[])
{
    errval_t err = filesystem_init();

    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "filesystem_init failed");
    }

    FILE *f = fopen("/dir2/dir2/test2.txt", "r");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }
    __attribute__((unused))
    const char *inspirational_quote = "I love deadlines. I like the whooshing "
                                      "sound they make as they fly by.";
    //size_t written = fwrite(inspirational_quote, 1, strlen(inspirational_quote), f);
    //printf("wrote %zu bytes\n", written);

    int c;
    do {
        c = fgetc(f);
        printf("%c", c);
    } while (c != EOF);

    return 0;
}