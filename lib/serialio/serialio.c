#include <aos/aos.h>
#include <serialio/serialio.h>

#include <maps/qemu_map.h>
#include <spawn/spawn.h>
#include <drivers/gic_dist.h>
#include <drivers/pl011.h>
#include <aos/inthandler.h>

#define SERIAL_MAX_LINE_SIZE 1024
#define SERIAL_MAX_HISTORY_SIZE 1024
#define MAX_OPEN_SESSIONS 1024

static bool serial_init = false;

struct session_state {
    size_t line_index;
    size_t char_index;
};

struct serial_state {
    size_t next_free_id;
    // circular buffer which stores the content of each
    char history[SERIAL_MAX_HISTORY_SIZE][SERIAL_MAX_LINE_SIZE];
    char line_length[SERIAL_MAX_LINE_SIZE]; // number of characters for each line
    size_t valid_lines; // how many lines in the history are valid
    size_t serial_line_index;
    size_t serial_char_index;
    struct session_state session_state[MAX_OPEN_SESSIONS];
    struct pl011_s *uart_state;
} serial_state;

__attribute__((unused))
static void serial_interrupt_handler(void *arg) {

    char c;
    pl011_getchar( serial_state.uart_state, &c);
    if (c == 4 || c == 10 || c == 13) {
        // 4: EOT, 10: NL, 13: CR
        // finish line and set pointer to a new empty line
        serial_state.history[serial_state.serial_line_index++][serial_state.serial_char_index] = '\0';
        serial_state.serial_char_index = 0;
        pl011_putchar(serial_state.uart_state, '\n');
    } else {
        serial_state.history[serial_state.serial_line_index][serial_state.serial_char_index++] = c;
        pl011_putchar(serial_state.uart_state, c);
    }
}

__attribute__((unused))
errval_t serial_get_char(struct aos_lmp *lmp, struct serialio_response *serial_response) {

    //DEBUG_PRINTF("Serial channel id: %zu \n", lmp->serial_channel_id);
    if(lmp->serial_channel_id == 0) {
        lmp->serial_channel_id = serial_state.next_free_id++;
    }

    if(serial_state.serial_char_index > 0) {
        //DEBUG_PRINTF("Sending char back: %c \n", serial_state.history[serial_state.serial_line_index][serial_state.serial_char_index-1]);
        serial_response->response_type = SERIAL_IO_SUCCESS;
        serial_response->c = serial_state.history[serial_state.serial_line_index][serial_state.serial_char_index-1];
        //DEBUG_PRINTF("Char in response: %c \n", serial_response->c);
        return SYS_ERR_OK;
    }

    serial_response->response_type = SERIAL_IO_NO_DATA;

    return SYS_ERR_OK;
}


errval_t init_serial_server(struct spawninfo *si) {
    DEBUG_PRINTF("INIT SERIAL SERVER \n");
    errval_t err;

    memset(&serial_state, 0, sizeof(struct serial_state));
    serial_state.next_free_id = 1;

    void *vbase_pl011;
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

    err = cap_retype(devframe_gic, dev_cap, QEMU_GIC_DIST_BASE - gic_dev_addr, ObjType_DevFrame, QEMU_GIC_DIST_SIZE, 1);

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

    /** Initialize the PL011 UART driver*/

    struct capref devframe_pl011;
    err = slot_alloc(&devframe_pl011);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate slot for pl011 frame \n");
    }

    genpaddr_t pl011_dev_addr;
    err = get_phys_addr(dev_cap, &pl011_dev_addr, NULL);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not get physical address for pl011 device\n");
    }

    err = cap_retype(devframe_pl011, dev_cap, QEMU_UART_BASE - pl011_dev_addr, ObjType_DevFrame, QEMU_UART_SIZE, 1);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not retype pl011 cap \n");
    }


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


    err = pl011_init(&serial_state.uart_state, (lvaddr_t *)vbase_pl011);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not init pl011 uart \n");
        return -1;
    }


    /** Obtain the IRQ destination cap and attach a handler to it */

    struct capref dst_cap;
    int vec_hint = QEMU_UART_INT; // ToDo: Change this if you're running on the board
    err = inthandler_alloc_dest_irq_cap(vec_hint, &dst_cap);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate destination cap for inthandler \n");
        return -1;
    }

    // ToDo: maybe better to use get_default_waitset(), but this throws an error. So use a new one for now
    struct waitset *ws;
    //waitset_init(&ws);
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
    err = gic_dist_enable_interrupt(gds, QEMU_UART_INT, cpu_targets, interrupt_priority);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not setup gic interrupt handler \n");
        return -1;
    }

    /** Enable the interrupt in the PL011 UART */

    err = pl011_enable_interrupt(serial_state.uart_state);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not enable interrupts for pl011 \n");
        return -1;
    }

    DEBUG_PRINTF("Finished initializing serial server! \n");
    serial_init = true;

    /*
    while (true) {
        err = event_dispatch(&ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }
     */

    return SYS_ERR_OK;
}
