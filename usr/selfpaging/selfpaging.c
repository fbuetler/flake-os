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
    printf("Hello World from thread %lu!\n", thread_id());

    size_t size = 50 * BASE_PAGE_SIZE;
    char *buf = malloc(size);

    for (size_t offset = 0; offset < size; offset+= BASE_PAGE_SIZE) {
        buf[offset] = 'a';
    }
    printf("Done in thread %lu \n", thread_id());

    return 0;
}

__attribute__((unused))
static int stack_test(void *arg)
{
    printf("Hello World from thread %lu!\n", thread_id());

    size_t size = 50 * BASE_PAGE_SIZE;
    char buf[size];

    for (size_t offset = 0; offset < size; offset+= BASE_PAGE_SIZE) {
        buf[offset] = 'a';
    }
    printf("Done in thread %lu \n", thread_id());

    return 0;
}

int main(int argc, char *argv[])
{
    int N = 50;
    struct thread *threads[N];
    printf("Inside main from selfpaging!\n");

    for(int i = 0; i < N; i++){
        threads[i] = thread_create(print_hello, NULL);
    }

    /*
    for(int i = 0; i < N; i++){
        int retval;
        thread_join(threads[i], &retval);
    }

    DEBUG_PRINTF("done with all threads\n");

    for(int i = 0; i < N; i++){
        threads[i] = thread_create(stack_test, NULL);
    }

    for(int i = 0; i < N; i++){
        int retval;
        thread_join(threads[i], &retval);
    }

    */
    DEBUG_PRINTF("done with all threads\n");

    return EXIT_SUCCESS;
}
