/**
 * \file
 * \brief Hello world application
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

int main(int argc, char *argv[])
{
    printf("Hello, world! from userspace\n");
    for (int i = 0; i < argc; i++) {
        printf("arg %d: %s\n", i, argv[i]);
    }
    printf("argument variable: (%p, %s)\n", argv, argv[0]);

    int stack_var = 27;
    printf("stack variable: (%p, %d)\n", &stack_var, stack_var);

    int *heap_variable = malloc(sizeof(int));
    *heap_variable = 42;
    printf("heap variable: (%p, %d)\n", &heap_variable, *heap_variable);

    return EXIT_SUCCESS;
}
