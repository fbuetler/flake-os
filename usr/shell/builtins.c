#include "builtins.h"
#include "helper.h"

#include <aos/aos_rpc.h>
#include <aos/aos.h>

void help(char **args) {
    write_str("Available commands:\n");
    write_str("help: this message\n");
    write_str("ps: print process status\n");
    write_str("kill: terminate a specific process\n");
    write_str("echo: write arguments back to screen\n");
}

void kill(char **args) {
    write_str("kill\n");
}

void spawn_hello(char **args) {
    abort();
    domainid_t pid;
    aos_rpc_process_spawn(get_init_rpc(), "hello", 0, &pid);
}

void ps(char **args) {
    domainid_t *pids;
    size_t pid_count;
    aos_rpc_process_get_all_pids(get_init_rpc(), &pids, &pid_count);
    DEBUG_PRINTF("pids count: %zu \n", pid_count);
    for (int i = 0; i < pid_count; i++) {
        DEBUG_PRINTF("received pid: 0x%x\n", pids[i]);
    }
}

void shell_exit(char **args) {
    abort();
    printf("exiting shell... \n");
    //write_str("exiting shell...\n");
    //shell_state.exit = true;

    /*
    size_t pid_count;
    domainid_t *pids;
    DEBUG_PRINTF("calling get_all_pids \n");
    aos_rpc_process_get_all_pids(shell_state.init_rpc, &pids, &pid_count);
    DEBUG_PRINTF("finished calling get_all_pids \n");
    DEBUG_PRINTF("PID count: %d\n", pid_count);

    for (int i = 0; i < pid_count; i++) {
        DEBUG_PRINTF("received pid: 0x%lx\n", pids[i]);
    }
     */
}

void echo(char **args) {
    printf("shell echo called \n");

    /*
    for (int i = 1; i < RECV_BUFFER_SIZE && args[i] != NULL; i++) {
        //write_str(strcat(args[i], " "));
        write_str(args[i]);
    }
    write_str("\n");
     */
}