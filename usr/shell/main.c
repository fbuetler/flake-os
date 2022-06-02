#include <stdio.h>
#include <aos/aos_rpc.h>
#include <getopt.h>

#include <time.h>
#include <sys/stat.h>
#include <fs/fs.h>

#include "builtins.h"
#include "helper.h"

char *builtin_str[] = {
    "help", "exit", "echo", "ps",    "run_bg", "run_fg", "ls",
    "pwd",  "cd",   "cat","mkdir", "rmdir", "rm", "fwrite",
};

void (*builtin_func[])(char *) = {
    &help, &shell_exit, &echo, &ps, &run_bg,   &run_fg,&ls,
    &pwd,  &cd,&cat,  &shell_mkdir, &shell_rmdir, &shell_rm, &shell_write,
};

int num_builtins(void)
{
    return sizeof(builtin_str) / sizeof(char *);
}

static void write_shell_prompt(void)
{
    write_str("[\e[32m");
    write_str(curr_fs_path);
    write_str("\e[0m]");
    write_str("$ ");
}

__attribute__((unused)) static void handle_input(void)
{
    // errval_t err;
    char c;
    // unsigned long start_time = 0;
    struct timespec start_time, end_time;

    write_shell_prompt();
    do {
        // err = aos_rpc_serial_getchar(shell_state.serial_rpc, &c);
        c = getchar();
        // DEBUG_PRINTF("recieved char: %c   %d\n", c, c);
        if (true) {
            if (c == 4 || c == 10 || c == 13) {
                // 4: EOT, 10: NL, 13: CR
                /* Enter is pressed. Parse the line and execute the command */
                shell_state.line_buffer[shell_state.buffer_count++] = '\0';
                aos_rpc_serial_putchar(shell_state.serial_rpc, '\n');

                // parse command
                // char *input_str = shell_state.line_buffer;
                // char *white_space = strchr(shell_state.line_buffer, ' ');

                char *command = strtok(shell_state.line_buffer, " ");

                bool timing = false;
                bool command_exists = false;

                if (command != NULL) {
                    // special handling of "time". This will start to track the time and
                    // set the input to the second argument such the following code is not
                    // aware of timing and can parse the input as normal
                    if (strcmp(command, "time") == 0) {
                        timing = true;
                        clock_gettime(CLOCK_MONOTONIC, &start_time);
                        command = strtok(NULL, " ");
                    }
                }


                if (command != NULL) {
                    // Simply pressing "enter" creates a '\0' string, which is treated as
                    // NULL strcmp does not support this and we don't want to write
                    // "command not found: (null)" but just write a blank line

                    for (int i = 0; i < num_builtins(); i++) {
                        if (strcmp(command, builtin_str[i]) == 0) {
                            // strtok with an empty string as delimiter returns the rest
                            // of the input. This can be a NULL pointer
                            builtin_func[i](strtok(NULL, ""));
                            command_exists = true;
                        }
                    }

                    if (!command_exists) {
                        // use printf instead of write_str to format string
                        if (timing) {
                            printf("time needs to be followed by a valid command\n");
                        } else {
                            printf("command not found: %s\n", command);
                        }
                    }
                }

                shell_state.buffer_count = 0;
                if (!shell_state.exit) {
                    // don't print anything if the shell is terminating
                    if (timing) {
                        clock_gettime(CLOCK_MONOTONIC, &end_time);
                        printf("elapsed: %ldus\n",
                               (end_time.tv_sec - start_time.tv_sec) * 1000000
                                   + (end_time.tv_nsec - start_time.tv_nsec) / 1000);
                    }
                    write_shell_prompt();
                }

            } else if (c == 8 || c == 127) {
                // Backspace. Note that on macos, pressing "backspace" actually sends "DEL"
                if (shell_state.buffer_count > 0) {
                    shell_state.buffer_count -= 1;
                    write_str("\e[D\e[K");  // move cursor to the left, clear until EOL
                }
            } else {
                if (shell_state.buffer_count >= RECV_BUFFER_SIZE - 1) {
                    write_str("\n");
                    write_str("Command too long!\n");
                    write_shell_prompt();
                    shell_state.buffer_count = 0;
                } else {
                    shell_state.line_buffer[shell_state.buffer_count++] = c;
                    aos_rpc_serial_putchar(shell_state.serial_rpc, c);
                }
            }
        }
    } while (!shell_state.exit);
}

int main(int argc, char *argv[])
{
    shell_state.serial_rpc = aos_rpc_get_serial_channel();
    shell_state.init_rpc = aos_rpc_get_init_channel();
    shell_state.buffer_count = 0;
    shell_state.exit = false;

    curr_fs_path = strdup(FS_MOUNTPOINT);

    filesystem_init();

    // Something to cheer you up while debugging
    write_str(" _______ ___     _______ ___   _ _______    _______ _______       \\__  __/  \n");
    write_str("|       |   |   |       |   | | |       |  |       |       |      /_/  \\_\\  \n");
    write_str("|    ___|   |   |   _   |   |_| |    ___|  |   _   |  _____|       _\\/\\/_  \n");
    write_str("|   |___|   |   |  |_|  |      _|   |___|  |  | |  | |_____   __/\\_\\_\\/_/_/\\__  \n");
    write_str("|    ___|   |___|       |     |_|    ___|  |  |_|  |_____  |    \\/ /_/\\_\\ \\/  \n");
    write_str("|   |   |       |   _   |    _  |   |___   |       |_____| |      __/\\/\\__  \n");
    write_str("|___|   |_______|__| |__|___| |_|_______|  |_______|_______|      \\_\\  /_/  \n");
    write_str("                                                                  /      \\ \n\n\n");

    do {
        handle_input();
    } while (!shell_state.exit);
}