#include <stdio.h>
#include <aos/aos_rpc.h>
#include <getopt.h>

#include "builtins.h"
#include "helper.h"

char *builtin_str[] = {
    "help",
    "exit",
    "echo",
    "spawn_hello",
    "ps",
    "kill"
};

void (*builtin_func[]) (char **) = {
    &help,
    &shell_exit,
    &echo,
    &spawn_hello,
    &ps,
    &kill,
};

int num_builtins(void) {
    return sizeof(builtin_str) / sizeof(char *);
}

static void handle_input(void) {
    errval_t err;
    char c;

    write_str("> ");
    do {
        err = aos_rpc_serial_getchar(shell_state.serial_rpc, &c);

        if(err == SYS_ERR_OK) {
            if (c == 4 || c == 10 || c == 13) {
                // 4: EOT, 10: NL, 13: CR
                /* Enter is pressed. Parse the line and execute the command */
                shell_state.line_buffer[shell_state.count++] = '\0';
                aos_rpc_serial_putchar(shell_state.serial_rpc, '\n');

                // parse command
                char * command = strtok(shell_state.line_buffer, " ");

                if(command != NULL) {
                    // Simply pressing "enter" creates a '\0' string, which is treated as NULL
                    // strcmp does not support this and we don't want to write "command not found: (null)" but
                    // just write a blank line
                    bool command_exists = false;
                    for (int i = 0; i < num_builtins(); i++) {
                        if (strcmp(command, builtin_str[i]) == 0) {
                            builtin_func[i](NULL);
                            command_exists = true;
                        }
                    }

                    if(!command_exists) {
                        // use printf instead of write_str to format string
                        printf("command not found: %s\n", command);
                    }
                }

                shell_state.count = 0;
                write_str("> ");

            } else if(c == 8 || c == 127) {
                // Backspace. Note that on macos, pressing "backspace" actually sends "DEL"
                if(shell_state.count > 0) {
                    shell_state.count -= 1;
                    write_str("\e[D\e[K");
                }
            }
            else {
                shell_state.line_buffer[shell_state.count++] = c;
                aos_rpc_serial_putchar(shell_state.serial_rpc, c);
            }
        }
        thread_yield(); // cooperative multitasking. Yield control to let other processes make progress, such as the serial_io library
    } while (!shell_state.exit);

}

int main(int argc, char *argv[])
{

    shell_state.serial_rpc = aos_rpc_get_serial_channel();
    shell_state.count = 0;
    shell_state.exit = false;

    DEBUG_PRINTF("shell started \n");

    do {
        handle_input();
    } while (!shell_state.exit);

}