/**
 * \file
 * \brief Self-Paging application
 */

/*
 * Copyright (c) 2022 Team 007 - License to slab
 * All rights reserved.
 */


#include <stdio.h>

#include <aos/aos.h>

static int print_hello(void *arg)
{
    printf("Hello World!\n");
    size_t size = 200 * BASE_PAGE_SIZE;
    char *buf = malloc(size);

    for (size_t offset = 0; offset < size; offset+= BASE_PAGE_SIZE) {
        DEBUG_PRINTF("starting iteration %d\n", offset/BASE_PAGE_SIZE);
        buf[offset] = 'a';
    }
    DEBUG_PRINTF("done\n");

    return 0;
}

int main(int argc, char *argv[])
{
    int N = 20;
    struct thread *threads[N];

    for(int i = 0; i < N; i++){
        threads[i] = thread_create(print_hello, NULL);
    }

    for(int i = 0; i < N; i++){
        int retval;
        thread_join(threads[i], &retval);
    }

    DEBUG_PRINTF("done with all threads\n");


    return EXIT_SUCCESS;
}
