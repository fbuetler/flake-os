#ifndef SHELL_HELPER_H
#define SHELL_HELPER_H
#include <aos/aos.h>

errval_t write_str(char *str);
errval_t spawn_process(char *args, domainid_t *pid);

#define RECV_BUFFER_SIZE 64

struct shell_state {
    bool exit; // flag to check if the shell should exit itself
    char line_buffer[RECV_BUFFER_SIZE];
    size_t buffer_count;
    struct aos_rpc *serial_rpc;
    struct aos_rpc *init_rpc;
} shell_state;

#endif
