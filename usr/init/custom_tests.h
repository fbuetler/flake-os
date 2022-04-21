/**
 * \file
 * \brief custom e2e tests
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_CUSTOM_E2E_TESTS_H_
#define _INIT_CUSTOM_E2E_TESTS_H_

#include <stdio.h>
#include <aos/aos.h>

// M1: physical memory management
void run_m1_tests(void);
// M2: paging (aka virtual memory) & process spawning
void run_m2_tests(void);
// M3: inter process communication
void run_m3_tests(void);
// M4: self paging
void run_m4_tests(void);
// M5: core spawing & simple inter core communication
void run_m5_tests(void);
// M6:
void run_m6_tests(void);

#endif /* _INIT_CUSTOM_E2E_TESTS_H_ */
