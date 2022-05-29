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
#include <fs/fat32fs.h>
#include <fs/dirent.h>
#include <fs/fs_rpc.h>
#include <aos/systime.h>
#include <aos/nameserver.h>

__attribute__((unused))
static void test_encode_decode(char *src){
    char encoded[12], result[12];
    fat32_encode_fname(src, encoded);
    fat32_decode_fname(encoded, result);
    printf("'%.11s' -> '%s'\n", encoded, result);
}

__attribute__((unused))
static void benchmark_read_total(struct fat32 *fat){
    printf("meature start\n");
    size_t start = systime_now();

    int iter = 50;
    for(int i = 0; i < iter; i++){
        //fat32_read_sector(fat, 100+i, &fat->data_scratch);
        sdhc_read_block(fat->sd, 100 + i, fat->data_scratch.phys);
    }
    size_t duration = systime_now() - start;

    printf("duration: %zu\n", systime_to_us(duration));

}

__attribute__((unused))
static void benchmark_read_no_flush(struct fat32 *fat){
    printf("meature start\n");
    size_t start = systime_now();

    int iter = 50;
    for(int i = 0; i < iter; i++){
        //fat32_read_sector(fat, 100+i, &fat->data_scratch);
        sdhc_read_block(fat->sd, 100 + i, fat->data_scratch.phys);
    }
    size_t duration = systime_now() - start;

    printf("duration: %zu\n", systime_to_us(duration));
}

__attribute__((unused))
static void benchmark_read(struct fat32 *fat){
    printf("meature start\n");

    int iter = 50;
    for(int i = 0; i < iter; i++){
        //fat32_read_sector(fat, 100+i, &fat->data_scratch);
        sdhc_read_block(fat->sd, 100 + i, fat->data_scratch.phys);
    }
}

__attribute__((unused))
static void benchmark_write_total(struct fat32 *fat){
    printf("meature start\n");
    size_t start = systime_now();

    int iter = 50;
    for(int i = 0; i < iter; i++){
        //fat32_read_sector(fat, 100+i, &fat->data_scratch);
        fat32_write_sector(fat, 100 + i, &fat->data_scratch);
    }
    size_t duration = systime_now() - start;

    printf("duration: %zu\n", systime_to_us(duration));

}

__attribute__((unused))
static void benchmark_write_no_flush(struct fat32 *fat){
    printf("meature start\n");
    size_t start = systime_now();

    int iter = 50;
    for(int i = 0; i < iter; i++){
        //fat32_read_sector(fat, 100+i, &fat->data_scratch);
        sdhc_write_block(fat->sd, 100 + i, fat->data_scratch.phys);
    }
    size_t duration = systime_now() - start;

    printf("duration: %zu\n", systime_to_us(duration));
}

__attribute__((unused))
static void benchmark_write(struct fat32 *fat){
    printf("meature start\n");

    int iter = 50;
    for(int i = 0; i < iter; i++){
        //fat32_read_sector(fat, 100+i, &fat->data_scratch);
        sdhc_write_block(fat->sd, 100 + i, fat->data_scratch.phys);
    }
}

int main(int argc, char *argv[])
{
    fs_init();

    fat32fs_mount(FS_MOUNTPOINT);

    errval_t err;

    char ccc = 0;
    err = nameservice_register(NS_FS_NAME, fs_srv_handler, (void *)&ccc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register fsreceive handler");
        return err;
    }

    printf("fs running\n");

    struct waitset *ws = get_default_waitset();
    while(1) {
        err = event_dispatch(ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "event_dispatch");
            return err;
        }
    }

    return 0;
}