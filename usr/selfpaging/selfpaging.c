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
    size_t size = 10 * BASE_PAGE_SIZE;
    char *buf = malloc(size);

    for (size_t offset = 0; offset < size; offset+= BASE_PAGE_SIZE) {
        buf[offset] = 'a';
        debug_printf("iter done\n");
    }

    debug_printf("donedonedone\n");

    return 0;
}

int main(int argc, char *argv[])
{
    /*struct thread *t = thread_create(print_hello, NULL);

    int retval;
    thread_join(t, &retval);*/

    print_hello(NULL);
    return EXIT_SUCCESS;
}
