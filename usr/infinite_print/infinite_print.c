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
    while(1){
        double d = 0;
        for(int i = 0; i < BIT(19); i++){
            d += i * d + 10;
        }
        printf("%finite_print!\n", d);
    }

    return EXIT_SUCCESS;
}
