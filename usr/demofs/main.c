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
#include <fs/fs.h>
#include <fs/fs_rpc_requests.h>

#define ITERS 3

char *buf1 = "aa";
char *buf2 = "aa";

static int thread_writer(void *buf){
    printf("starting thread_writer\n");
    FILE *f = fopen("/sdcard/test.txt", "w");
    assert(f);
    for(int i = 0; i < ITERS; i++){
       fwrite(buf, 1, strlen(buf), f); 
       fflush(f);

       printf("1 iter %d\n", i);
    }
    fclose(f);
    return 0;
}

__attribute__((unused))
static int thread_rm_while_open(void *st){
    printf("starting thread_rm_while_open\n");
    barrelfish_usleep(2 * 1000* 1000);

    errval_t err = rm("/sdcard/test.txt");
    assert(err_is_fail(err));
    return 0;
}

__attribute__((unused))
static void check_rm_while_invalid(void){
    int retval;
    struct thread *t = thread_create(thread_writer, buf2);
    thread_rm_while_open(NULL);
    thread_join(t, &retval);
}

__attribute__((unused))
static void check_concurrent_writers(void){
    int retval;
    struct thread *t = thread_create(thread_writer, buf1);
    thread_writer(buf2);
    thread_join(t, &retval);

    FILE *f = fopen("/sdcard/test.txt", "r");
    // print content
    while(1){
        int c;
        c = fgetc(f);
        if(c == EOF)
            break;

        printf("%c", c);
    }
    printf("\n");
}

static void check_rm(void){
    printf("MKDIR testdir2\n");
    assert(err_is_ok(mkdir("/sdcard/testdir2")));
    printf("create testdir2/f2.txt\n");
    FILE *f = fopen("/sdcard/testdir2/f2.txt", "w");
    assert(f);
    printf("closing testdir2/f2.txt\n");
    fclose(f);

    printf("create testdir2/f3.txt\n");
    f = fopen("/sdcard/testdir2/f3.txt", "w");
    assert(f);
    printf("closing testdir2/f3.txt\n");
    fclose(f);

    printf("RM testdir2/f3.txt\n");
    rm("/sdcard/testdir2/f3.txt");
    printf("check: RMDIR testdir2 fails\n");
    assert(err_is_fail(rmdir("/sdcard/testdir2")));

    printf("RM testdir2/f2.txt\n");
    rm("/sdcard/testdir2/f2.txt");

    printf("check: RM testdir2 fails\n");
    assert(err_is_fail(rm("/sdcard/testdir2")));
    printf("RMDIR testdir2\n");
    assert(err_is_ok(rmdir("/sdcard/testdir2")));

}

int main(int argc, char *argv[])
{
    filesystem_init();

    check_rm();

    DEBUG_PRINTF("check_rm done!!\n");

    //check_rm_while_invalid();
    //check_concurrent_writers();

    
    printf("done\n");
    return 0;
    
}