#include <aos/aos.h>
#include <serialio/serialio.h>

#include <maps/qemu_map.h>
#include <spawn/spawn.h>
#include <drivers/gic_dist.h>
#include <drivers/pl011.h>
#include <drivers/lpuart.h>
#include <aos/inthandler.h>
#include <maps/imx8x_map.h>

#define SERIAL_BUFFER_SIZE 1024 //ToDo: what's a good size?

static bool serial_init = false; // flag to make sure that no function gets called before initialization happened

struct serial_state {
    char buffer[SERIAL_BUFFER_SIZE]; // ring buffer
    size_t next_write; /// position in the ring buffer for the next write
    size_t next_read; /// position in the ring buffer for the next read
    size_t num_valid_entries; /// count how many entries entries are valid
    bool empty; // true if the buffer is empty

    union uart{
        struct pl011_s *pl011;
        struct lpuart_s *lpuart;
    } uart;

    enum serialio_type uart_type;

    //struct pl011_s *uart_state;
    struct thread_mutex lock;
} serial_state;

static void serial_interrupt_handler(void *arg) {
    thread_mutex_lock(&serial_state.lock); // buffer shouldn't be modified while it is being read

    // read char, put it into buffer, wrap around if necessary
    char c;
    switch (serial_state.uart_type) {
    case UART_QEMU:
        pl011_getchar( serial_state.uart.pl011, &c);
        break;
    case UART_TORADEX:
        lpuart_getchar(serial_state.uart.lpuart, &c);
        break;
    }

    if(!serial_state.empty && serial_state.next_read == serial_state.next_write) {
       serial_state.next_read = (serial_state.next_read+1)%SERIAL_BUFFER_SIZE;
    }

    serial_state.buffer[serial_state.next_write++] = c;
    serial_state.next_write %= SERIAL_BUFFER_SIZE;
    serial_state.empty = false;

    thread_mutex_unlock(&serial_state.lock);
}

errval_t serial_put_char(struct aos_lmp *lmp, const char *c) {
    if(!serial_init)
        return SERIAL_IO_NO_DATA; // todo: improve error

    //ToDo: are locks required?
    switch (serial_state.uart_type) {
    case UART_QEMU:
        // workaround because the picocom terminal requires a carriage return to start a new line at the beginning
        if(*c == '\n')
            pl011_putchar( serial_state.uart.pl011, '\r');
        pl011_putchar( serial_state.uart.pl011, *c);
        break;
    case UART_TORADEX:
        if(*c == '\n')
            lpuart_putchar( serial_state.uart.lpuart, '\r');
        lpuart_putchar(serial_state.uart.lpuart, *c);
        break;
    }

    return SYS_ERR_OK;
}

__attribute__((unused))
errval_t serial_get_char(struct aos_lmp *lmp, struct serialio_response *serial_response) {
    if(!serial_init)
        return SERIAL_IO_NO_DATA; // todo: improve error

    thread_mutex_lock(&serial_state.lock);

    serial_response->response_type = SERIAL_IO_NO_DATA;
    if(!serial_state.empty) {
        serial_response->c = serial_state.buffer[serial_state.next_read++];
        serial_state.next_read %= SERIAL_BUFFER_SIZE;
        serial_state.empty = (serial_state.next_read == serial_state.next_write);
        serial_response->response_type = SERIAL_IO_SUCCESS;
    }

    thread_mutex_unlock(&serial_state.lock);
    return SYS_ERR_OK;
}


errval_t init_serial_server(enum serialio_type uart_type) {
    DEBUG_PRINTF("INIT SERIAL SERVER\n");

    memset(&serial_state, 0, sizeof(struct serial_state));
    thread_mutex_init(&serial_state.lock);

    serial_state.empty = true;
    serial_state.uart_type = uart_type;


    long GIC_DIST_BASE, GIC_DIST_SIZE, UART_BASE, UART_SIZE;
    int VEC_HINT, UART_INT;
    switch (uart_type) {
    case UART_QEMU:
        GIC_DIST_BASE = QEMU_GIC_DIST_BASE;
        GIC_DIST_SIZE = QEMU_GIC_DIST_SIZE;
        UART_BASE = QEMU_UART_BASE;
        UART_SIZE = QEMU_UART_SIZE;
        VEC_HINT = QEMU_UART_INT;
        UART_INT = QEMU_UART_INT;
        break;
    case UART_TORADEX:
        GIC_DIST_BASE = IMX8X_GIC_DIST_BASE;
        GIC_DIST_SIZE = IMX8X_GIC_DIST_SIZE;
        UART_BASE = IMX8X_UART3_BASE; // hard-coded as this is specific to our board
        UART_SIZE = IMX8X_UART_SIZE;
        VEC_HINT = IMX8X_UART3_INT;
        UART_INT = IMX8X_UART3_INT;
        break;
    default:
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    errval_t err;
    void *vbase_uart;
    void *vbase_gic;
    struct gic_dist_s *gds;

    struct capref dev_cap = (struct capref) {
        .cnode = cnode_task,
        .slot = TASKCN_SLOT_DEV,
    };

    /** Initialize the GIC distributor driver */

    struct capref devframe_gic;
    err = slot_alloc(&devframe_gic);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate slot for GIC frame \n");
    }

    genpaddr_t gic_dev_addr;
    err = get_phys_addr(dev_cap, &gic_dev_addr, NULL);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not get physical address for GIC device\n");
    }

    err = cap_retype(devframe_gic, dev_cap, GIC_DIST_BASE - gic_dev_addr, ObjType_DevFrame, GIC_DIST_SIZE, 1);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not retype GIC cap \n");
    }

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

    /** Initialize the UART driver*/

    struct capref devframe_uart;
    err = slot_alloc(&devframe_uart);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate slot for UART frame \n");
    }

    genpaddr_t uart_dev_addr;
    err = get_phys_addr(dev_cap, &uart_dev_addr, NULL);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not get physical address for pl011 device\n");
    }

    err = cap_retype(devframe_uart, dev_cap, UART_BASE - uart_dev_addr, ObjType_DevFrame, UART_SIZE, 1);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not retype UART cap \n");
    }


    err = paging_map_frame_attr(get_current_paging_state(), &vbase_uart, PAGE_SIZE,
                                devframe_uart, VREGION_FLAGS_READ_WRITE_NOCACHE);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not map UART registers\n");
        return -1;
    }

    if((void*)vbase_uart == NULL) {
        DEBUG_PRINTF("Could not map UART registers, region is empty \n");
        return -1;
    }

    switch (uart_type) {
    case UART_QEMU:
        err = pl011_init(&serial_state.uart.pl011, (lvaddr_t *)vbase_uart);
        break;
    case UART_TORADEX:
        err = lpuart_init(&serial_state.uart.lpuart, (lvaddr_t *)vbase_uart);
        break;
    }

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not init UART \n");
        return -1;
    }


    /** Obtain the IRQ destination cap and attach a handler to it */

    struct capref dst_cap;
    err = inthandler_alloc_dest_irq_cap(VEC_HINT, &dst_cap);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate destination cap for inthandler \n");
        return -1;
    }

    // ToDo: maybe better to use get_default_waitset(), but this throws an error. So use a new one for now
    struct waitset *ws;
    ws = get_default_waitset();
    err = inthandler_setup(dst_cap, ws, MKCLOSURE(serial_interrupt_handler, NULL));

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not setup inthandler \n");
        return -1;
    }


    /** Enable the interrupt in the GIC distributor */

    uint16_t interrupt_priority = 0; // ToDo: couldn't find correct ARM documentation for this
    uint8_t cpu_targets = 1; // ToDo: add multicore support ? Read from gds?

    // ToDo: Change int_id if you're running on the board
    err = gic_dist_enable_interrupt(gds, UART_INT, cpu_targets, interrupt_priority);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not setup gic interrupt handler \n");
        return -1;
    }

    /** Enable the interrupt in the UART */

    switch (uart_type) {
    case UART_QEMU:
        err = pl011_enable_interrupt(serial_state.uart.pl011);
        break;
    case UART_TORADEX:
        err = lpuart_enable_interrupt(serial_state.uart.lpuart);
        break;
    }

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not enable interrupts for pl011 \n");
        return -1;
    }

    DEBUG_PRINTF("Finished initializing serial server! \n");

    serial_init = true;

    return SYS_ERR_OK;
}
