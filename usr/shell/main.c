#include <stdio.h>

#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/paging.h>

#include <aos/inthandler.h>

#include <drivers/pl011.h>
#include <drivers/gic_dist.h>
#include <drivers/lpuart.h>


#include <maps/qemu_map.h>

//#include <offsets.h>

__attribute__((unused))
static void interrupt_handler(void *arg) {
    DEBUG_PRINTF("Inside interrupt handler of shell \n");
    /*
    errvalt err;
    char c;
    err = pl011_getchar(s, &c);
    */
}

int main(int argc, char *argv[])
{
    DEBUG_PRINTF("Shell Started\n");

    errval_t err;

    struct pl011_s *s_pl;
    //struct lpuart_s *s_lp;
    void *vbase_pl011;
    void *vbase_gic;
    struct gic_dist_s *gds;

    /* Initialize the GIC distributor driver */

    struct capref devframe_gic = (struct capref) {
        .cnode = cnode_arg,
        .slot = ARGCN_SLOT_DEVFRAME
    };

    err = paging_map_frame_attr(get_current_paging_state(), &vbase_gic, PAGE_SIZE,
                                devframe_gic, VREGION_FLAGS_READ_WRITE_NOCACHE);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not map GIC registers\n");
        return -1;
    }

    if((void*)vbase_gic == NULL) {
        DEBUG_PRINTF("Could not map GIC registers, region is empty \n");
        return -1;
    }

    err = gic_dist_init(&gds, (lvaddr_t *)vbase_gic);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not initialize GIC distr driver\n");
        return -1;
    }

    /* Initialize the LPUART driver*/

    struct capref devframe_pl011 = (struct capref) {
        .cnode = cnode_arg,
        .slot = ARGCN_SLOT_DEVFRAME
    };

    err = paging_map_frame_attr(get_current_paging_state(), &vbase_pl011, PAGE_SIZE,
                                devframe_pl011, VREGION_FLAGS_READ_WRITE_NOCACHE);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not map pl011 registers\n");
        return -1;
    }

    if((void*)vbase_pl011 == NULL) {
        DEBUG_PRINTF("Could not map pl011 registers, region is empty \n");
        return -1;
    }

    err = pl011_init(&s_pl, (lvaddr_t *)vbase_pl011);
    //err = lpuart_init(&s_lp, (lvaddr_t *)vbase_pl011);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not init pl011 uart \n");
        return -1;
    }

    /* Obtain the IRQ destination cap and attach a handler to it */
#if 0
    struct capref dst_cap;
    int vec_hint = QEMU_UART_INT; // ToDo: what value is expected? They are in lpuart.h
    err = inthandler_alloc_dest_irq_cap(vec_hint, &dst_cap);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate destination cap for inthandler \n");
        return -1;
    }

    err = inthandler_setup(dst_cap, get_default_waitset(), MKCLOSURE(interrupt_handler, NULL));

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not setup inthandler \n");
        return -1;
    }

    /* Enable the interrupt in the GIC distributor */

    uint16_t interrupt_priority = 0; // ToDo: couldn't find correct ARM documentation for this
    uint8_t cpu_targets = 1; // ToDo: add multicore support ? Read from gds?

    gic_dist_enable_interrupt(gds, QEMU_UART_INT, cpu_targets, interrupt_priority);


    /* Enable the interrupt in the LPUART */

    err = pl011_enable_interrupt(s_pl);
    //err = lpuart_enable_interrupt(s_lp);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not enable interrupts for pl011 \n");
        return -1;
    }
#endif

    while(true) {
        char c;
        do {
            err = pl011_getchar(s_pl, &c);
        }while(err == LPUART_ERR_NO_DATA);
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "Could not fetch char from pl011 uart \n");
            return -1;
        }
        pl011_putchar(s_pl, c);
    }

    /* done? */
    pl011_putchar(s_pl, '\n');
    pl011_putchar(s_pl, 'x');
    pl011_putchar(s_pl, '\n');

#if 0
    while (true) {
        err = event_dispatch(get_default_waitset());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }
#endif
    DEBUG_PRINTF("Exiting Shell \n");


}