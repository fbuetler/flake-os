/**
 * \file
 * \brief Serial port driver.
 */

/*
 * Copyright (c) 2020, ETH Zurich.
 * Copyright (c) 2022, The University of British Columbia.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <drivers/pl011.h>
#include <dev/pl011_uart_dev.h>

struct pl011_s {
    struct event_closure int_handler;
    struct pl011_uart_t dev;
};


static void hw_init(struct pl011_s *s)
{
    pl011_uart_t *u = &s->dev;

    /* Mask all interrupts: set all bits to zero. */
    pl011_uart_IMSC_rawwr(u, 0);

    /* Disable the UART before reconfiguring it. */
    pl011_uart_CR_uarten_wrf(u, 0);

    // Configure port to 38400 baud, 8 data, no parity, 1 stop (8-N-1)
    //
    // (This is a mild scam as system is running in QEMU)
    //
    // Note baud rate changes not committed in h/w until lcr_h
    // written.
    pl011_uart_IBRD_divint_wrf(u, 0xc);  // Assuming UARTCLK is 7.3728MHz
    pl011_uart_FBRD_divfrac_wrf(u, 0);

    /* Configure the line control register. */
    pl011_uart_LCR_H_t lcr = (pl011_uart_LCR_H_t)0;
    /* Disable FIFOs.  There's no way to get an interrupt when a single
     * character arrives with FIFOs, so it's useless as a console. */
    lcr = pl011_uart_LCR_H_fen_insert(lcr, 0);
    /* Eight data bits. */
    lcr = pl011_uart_LCR_H_wlen_insert(lcr, pl011_uart_bits8);
    /* No parity. */
    lcr = pl011_uart_LCR_H_pen_insert(lcr, 0);
    /* One stop bit. */
    lcr = pl011_uart_LCR_H_stp2_insert(lcr, 0);
    pl011_uart_LCR_H_wr(u, lcr);

    /* Configure the main control register. */
    pl011_uart_CR_t cr = (pl011_uart_CR_t)0;
    /* No flow control. */
    cr = pl011_uart_CR_ctsen_insert(cr, 0);
    cr = pl011_uart_CR_rtsen_insert(cr, 0);
    /* Enable transmit and receive. */
    cr = pl011_uart_CR_txe_insert(cr, 1);
    cr = pl011_uart_CR_rxe_insert(cr, 1);
    /* Enable UART. */
    cr = pl011_uart_CR_uarten_insert(cr, 1);
    pl011_uart_CR_wr(u, cr);
}

errval_t pl011_init(struct pl011_s **s_ret, void *base)
{
    PL011_DEBUG("Driver init\n");

    assert(s_ret != NULL);
    assert(base != NULL);

    struct pl011_s *s = calloc(1, sizeof(struct pl011_s));
    if (s == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    *s_ret = s;

    pl011_uart_initialize(&s->dev, base);

    PL011_DEBUG("Initializing hw...");
    hw_init(s);
    return SYS_ERR_OK;
}

errval_t pl011_getchar(struct pl011_s *s, char *c)
{
    pl011_uart_t *u = &s->dev;
    assert(u->base != 0);

    /* Acknowledge any interrupt. */
    pl011_uart_ICR_rxic_wrf(u, 1);

    /* check if there is data */
    if (pl011_uart_FR_rxfe_rdf(u) == 1) {
        return LPUART_ERR_NO_DATA;
    }

    /* store the return character */
    *c = (char)pl011_uart_DR_data_rdf(u);

    return SYS_ERR_OK;
}

errval_t pl011_enable_interrupt(struct pl011_s *s)
{
    pl011_uart_t *u = &s->dev;
    assert(u->base != 0);

    // Receive interrupt enable
    pl011_uart_ICR_rxic_wrf(u, 1);
    pl011_uart_IMSC_rxim_wrf(u, 1);
    return SYS_ERR_OK;
}

errval_t pl011_putchar(struct pl011_s *s, char c)
{
    pl011_uart_t *u = &s->dev;
    assert(u->base != 0);

    while (pl011_uart_FR_txff_rdf(u) == 1)
        ;
    pl011_uart_DR_rawwr(u, c);

    return SYS_ERR_OK;
}
