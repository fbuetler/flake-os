/**
 * \file
 * \brief Physical memory map for the QEMU Virt Platform
 */

/*
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich.
 * Attn: Systems Group.
 */

#ifndef QEMU_MAP_H
#define QEMU_MAP_H


#define QEMU_SPI_INTERRUPTS_START 32

/*
 * UART
 */

#define QEMU_UART_BASE 0x09000000
#define QEMU_UART_SIZE 0x1000
#define QEMU_UART_INT  (QEMU_SPI_INTERRUPTS_START + PL011_UART0_INT)
/*
 * GIC Distributor
 */
#define QEMU_GIC_DIST_BASE 0x08000000
#define QEMU_GIC_DIST_SIZE 0x1000



#endif  // QEMU_MAP_H
