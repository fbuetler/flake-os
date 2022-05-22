#ifndef SHELL_HELPER_H
#define SHELL_HELPER_H
#include <aos/aos.h>

errval_t write_str(char *str);

#define RECV_BUFFER_SIZE 1024

struct shell_state {
    bool exit; // flag to check if the shell should exit itself
    char line_buffer[RECV_BUFFER_SIZE];
    size_t count;
    struct aos_rpc *serial_rpc;
} shell_state;

#endif
