/*
 * Copyright (c) 2020, ETH Zurich.
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr 6, CH-8092 Zurich.
 */

#ifndef PL011_H_
#define PL011_H_

#include <stdint.h>
#include <aos/aos.h>

//#define PL011_DEBUG_ON
#if defined(PL011_DEBUG_ON)
#define PL011_DEBUG(x...) debug_printf("pl011:" x)
#else
#define PL011_DEBUG(x...) ((void)0)
#endif

#define PL011_UART0_INT 1

struct pl011_s;

errval_t pl011_init(struct pl011_s** s, void *base);
errval_t pl011_enable_interrupt(struct pl011_s * s);
errval_t pl011_putchar(struct pl011_s* s, char c);
errval_t pl011_getchar(struct pl011_s* s, char *c);


#endif
