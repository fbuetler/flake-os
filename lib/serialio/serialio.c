#include <aos/aos.h>
#include <serialio/serialio.h>

#include <maps/qemu_map.h>
#include <spawn/spawn.h>
#include <drivers/gic_dist.h>
#include <drivers/pl011.h>
#include <aos/inthandler.h>

#define SERIAL_BUFFER_SIZE 1024
#define MAX_OPEN_SESSIONS 1024

static bool serial_init = false;

/*
struct session_state {
    size_t char_index;
};
 */

struct serial_state {
    // circular buffer which stores the content of each
    char buffer[SERIAL_BUFFER_SIZE];
    size_t next_free_id; /// next free session id
    // numbers are easier to work with than _real_ pointers because wrap around can be computed with modulo
    size_t next_write;
    size_t next_read;
    size_t num_valid_entries; /// count how many entries entries are valid
    bool empty;

    /*
    size_t oldest_entry; /// pointer to the oldest char in the buffer
    size_t next_free_entry; /// pointer to the next free entry in the buffer
     */

    //struct session_state session_state[MAX_OPEN_SESSIONS];
    struct pl011_s *uart_state;
    struct thread_mutex lock;
} serial_state;

__attribute__((unused))
static void serial_interrupt_handler(void *arg) {
    thread_mutex_lock(&serial_state.lock); // buffer shouldn't be modified while it is being read

    // read char, put it into buffer, wrap around if necessary
    char c;
    pl011_getchar( serial_state.uart_state, &c);
    if(!serial_state.empty && serial_state.next_read == serial_state.next_write) {
       serial_state.next_read = (serial_state.next_read+1)%SERIAL_BUFFER_SIZE;
    }

    serial_state.buffer[serial_state.next_write++] = c;
    serial_state.next_write %= SERIAL_BUFFER_SIZE;
    serial_state.empty = false;


    //serial_state.num_valid_entries = MAX(SERIAL_BUFFER_SIZE, serial_state.num_valid_entries+1); // after wrap around, everything is valid
    /*
    // after the buffer has wrapped once, the
    if(serial_state.num_valid_entries == SERIAL_BUFFER_SIZE) {
        if(serial_state.next_read < serial_state.next_write)
       for (int i = 0; i < serial_state.next_free_id; ++i) {
           if (serial_state.session_state[i].char_index < serial_state.next_free_entry) {
               serial_state.session_state->char_index = serial_state.next_free_entry;
           }
       }
    } */

    thread_mutex_unlock(&serial_state.lock);
}

errval_t serial_put_char(struct aos_lmp *lmp, const char *c) {
    pl011_putchar(serial_state.uart_state, *c);
    return SYS_ERR_OK;
}

__attribute__((unused))
errval_t serial_get_char(struct aos_lmp *lmp, struct serialio_response *serial_response) {
    thread_mutex_lock(&serial_state.lock);

    /*
    size_t internal_session_id;
    //DEBUG_PRINTF("Serial channel id: %zu \n", lmp->serial_channel_id);
    if(lmp->serial_channel_id == 0) {
        lmp->serial_channel_id = (serial_state.next_free_id++)+1;  // 0 is reserved for "no_session"
    }
    internal_session_id = lmp->serial_channel_id-1;
     */

    serial_response->response_type = SERIAL_IO_NO_DATA;
    if(!serial_state.empty) {
        serial_response->c = serial_state.buffer[serial_state.next_read++];
        serial_state.next_read %= SERIAL_BUFFER_SIZE;
        serial_state.empty = (serial_state.next_read == serial_state.next_write);
        serial_response->response_type = SERIAL_IO_SUCCESS;
    }

    /*
    // ToDo: change initial position to oldest entry
    //serial_state.session_state[internal_session_id]



    if(serial_state.session_state[internal_session_id].line_index == serial_state.serial_line_index) {
        // reading from line where input is currently writing onto
        if(serial_state.session_state[internal_session_id].char_index < serial_state.serial_char_index) {
            serial_response->c = serial_state.history[serial_state.session_state[internal_session_id].line_index][serial_state.session_state[internal_session_id].char_index++];
        }
    }

    if(serial_state.session_state[internal_session_id].line_index < serial_state.serial_line_index) {
        // reading inside a line from the history
        size_t line_length = serial_state.line_length[serial_state.session_state[internal_session_id].line_index];
        if(serial_state.session_state[internal_session_id].char_index < line_length) {
            serial_response->c = serial_state.history[serial_state.session_state[internal_session_id].line_index][serial_state.session_state[internal_session_id].char_index++];
            serial_response->response_type = SERIAL_IO_SUCCESS;

            // after advancing pointer, check that it's still valid. Otherwise advance line
            if(serial_state.session_state[internal_session_id].char_index >= line_length) {
                serial_state.session_state[internal_session_id].char_index = 0;
                serial_state.session_state[internal_session_id].line_index += 1;
            }
        }
    }

     */
    thread_mutex_unlock(&serial_state.lock);
    return SYS_ERR_OK;
}


errval_t init_serial_server(enum serialio_type uart_type) {
    DEBUG_PRINTF("INIT SERIAL SERVER \n");

    if(uart_type != UART_QEMU) {
        DEBUG_PRINTF("Only QEMU serial server is currently supported! \n");
        abort();
    }

    errval_t err;

    memset(&serial_state, 0, sizeof(struct serial_state));

    thread_mutex_init(&serial_state.lock);
    serial_state.next_free_id = 0;
    serial_state.empty = true;

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
