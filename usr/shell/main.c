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

// basic functionality for input parsing from: https://brennan.io/2015/01/16/write-a-shell-in-c/

#define RECV_BUFFER_SIZE 1024

errval_t write_str(char *str);
static void new_shell_line(void);
errval_t write_nstr(char *str, size_t len);

int num_builtins(void);

struct shell_state {
    struct pl011_s *uart_state;
} shell_state;

// ring buffer to recv data. tail is current position, head is initial position. tail moves for each new entry
struct receive_state {
    size_t count;
    char data[RECV_BUFFER_SIZE];
} recv_state;


char *builtin_str[] = {
    "help",
    "exit",
    "echo"
};

void shell_help(char **args);
void shell_exit(char **args);
void shell_echo(char **args);


void (*builtin_func[]) (char **) = {
    &shell_help,
    &shell_exit,
    &shell_echo
};

int num_builtins(void) {
    return sizeof(builtin_str) / sizeof(char *);
}

void shell_help(char **args) {
    write_str("Available commands:\n");
    write_str("help: This message\n");
    write_str("echo: Repeat the input\n");
    write_str("exit: NYI\n");
}

void shell_exit(char **args) {
    write_str("2222\n");
}

void shell_echo(char **args) {
    for (int i = 1; i < RECV_BUFFER_SIZE && args[i] != NULL; i++) {
        //write_str(strcat(args[i], " "));
        write_str(args[i]);
    }
    write_str("\n");
}


static void handle_line(void) {
    size_t token_counter ;
    char *tokens[RECV_BUFFER_SIZE];

    token_counter = 0;
    char *line = &recv_state.data[0];

    // tokenize
    char *token;
    token = strtok(line, " ");

    while (token != NULL) {
        tokens[token_counter++] = token;
        DEBUG_PRINTF("token: %s \n", token);
        token = strtok(NULL, " ");
    }
    tokens[token_counter] = NULL;

    // parsing
    if(tokens[0] == NULL) {
        char *o = "No command was entered. Type 'help' for help\n";
        write_str(o);
    } else {
        for (int i = 0; i < num_builtins(); i++) {
            if (strcmp(tokens[0], builtin_str[i]) == 0) {
                builtin_func[i](tokens);
                return;
            }
        }
        char *o = "Unknown command. Type 'help' for help\n";
        write_str(o);
    }
}

static void new_shell_line(void) {
    recv_state.count = 0;
    write_str("> ");
}

__attribute__((unused))
static void interrupt_handler(void *arg) {
    /**
     * This function gets called every time the UART driver recieves a new character.
     * Besides special character (explained later), every character is put into a ring-buffer
     * and printed on screen.
     * Special characters:
     *  - EOT/NL/CR: User pressed "Enter". Writes a new line and calls the handle_line function to process the input
     *  - BS/DEL (Backspace): On-screen: Clear current cell and move cursor one cell to the left. Removes char from the buffer
     */
    char c;
    pl011_getchar(shell_state.uart_state, &c);

    if (c == 4 || c == 10 || c == 13) {
        // 4: EOT, 10: NL, 13: CR
        /* Enter is pressed. Parse the line and execute the command */
        recv_state.data[recv_state.count++] = '\0';
        pl011_putchar(shell_state.uart_state, '\n');
        handle_line();
        new_shell_line();

    } else if(c == 8 || c == 127) {
        // Backspace. Note that on macos, pressing "backspace" actually sends "DEL"
        if(recv_state.count > 0) {
            recv_state.count -= 1;
            write_str("\e[D\e[K"); // kills current cell, moves cursor to the left
        }

    } else {
        if(recv_state.count == RECV_BUFFER_SIZE-1) {
            write_str("\n Command too long.\n");
            new_shell_line();
        } else {
            recv_state.data[recv_state.count++] = c;
            pl011_putchar(shell_state.uart_state, c);
        }
    }
}

errval_t write_str(char *str) {
    errval_t err = SYS_ERR_OK;
    for (int i = 0; i < strlen(str); ++i) {
        pl011_putchar(shell_state.uart_state, str[i]);
    }
    return err;
}

errval_t write_nstr(char *str, size_t len) {
    errval_t err = SYS_ERR_OK;
    for (int i = 0; i < len; ++i) {
        pl011_putchar(shell_state.uart_state, str[i]);
    }
    return err;
}

int main(int argc, char *argv[])
{
    DEBUG_PRINTF("shell starting\n");

    errval_t err;

    //struct lpuart_s *s_lp;
    void *vbase_pl011;
    void *vbase_gic;
    struct gic_dist_s *gds;

    /* Initialize the GIC distributor driver */

    struct capref devframe_gic = (struct capref) {
        .cnode = cnode_arg,
        .slot = ARGCN_SLOT_DEVFRAME_IRQ
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

    /* Initialize the PL011 UART driver*/

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

    err = pl011_init(&shell_state.uart_state, (lvaddr_t *)vbase_pl011);
    //err = lpuart_init(&s_lp, (lvaddr_t *)vbase_pl011);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not init pl011 uart \n");
        return -1;
    }

    /* Obtain the IRQ destination cap and attach a handler to it */

    struct capref dst_cap;
    int vec_hint = QEMU_UART_INT; // ToDo: Change this if you're running on the board
    err = inthandler_alloc_dest_irq_cap(vec_hint, &dst_cap);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not allocate destination cap for inthandler \n");
        return -1;
    }

    // ToDo: maybe better to use get_default_waitset(), but this throws an error. So use a new one for now
    struct waitset ws;
    waitset_init(&ws);
    err = inthandler_setup(dst_cap, &ws, MKCLOSURE(interrupt_handler, NULL));

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not setup inthandler \n");
        return -1;
    }

    /* Enable the interrupt in the GIC distributor */

    uint16_t interrupt_priority = 0; // ToDo: couldn't find correct ARM documentation for this
    uint8_t cpu_targets = 1; // ToDo: add multicore support ? Read from gds?

    // ToDo: Change int_id if you're running on the board
    err = gic_dist_enable_interrupt(gds, QEMU_UART_INT, cpu_targets, interrupt_priority);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not setup gic interrupt handler \n");
        return -1;
    }

    /* Enable the interrupt in the PL011 UART */

    err = pl011_enable_interrupt(shell_state.uart_state);
    //err = lpuart_enable_interrupt(s_lp);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not enable interrupts for pl011 \n");
        return -1;
    }

    DEBUG_PRINTF("shell ready\n");
    write_str("> ");

    while (true) {
        err = event_dispatch(&ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    DEBUG_PRINTF("Exiting Shell \n");


}