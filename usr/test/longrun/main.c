/**
 * \file
 * \brief file system test application
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
#include <aos/systime.h>

#define BUFSIZE 500
#define MAX_MALLOC_LEN 4096

int main(int argc, char *argv[])
{
    void *buf[BUFSIZE];

    for (int i = 0; i < BUFSIZE; i++) {
        int size = rand() % MAX_MALLOC_LEN;
        buf[i] = malloc(size);
        printf("malloced %d bytes\n", size);
        assert(buf[i] != NULL);
    }

    int i = 0; 
    while(1){
        debug_printf("iter: %d\n", i);

        free(buf[i]);
        int size = rand() % MAX_MALLOC_LEN;
        buf[i] = malloc(size);
        printf("malloced %d bytes\n", size);

        i = (i + 1) % BUFSIZE;
    }
    
    return EXIT_SUCCESS;
}
