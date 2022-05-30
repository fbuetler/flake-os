#include "builtins.h"
#include "helper.h"

#include <aos/aos_rpc.h>
#include <aos/aos.h>

void help(char *args) {
    write_str("Available commands:\n");
    write_str("help: this message\n");
    write_str("ps: TODO print process status\n");
    write_str("kill: TODO terminate a specific process\n");
    write_str("echo: write arguments back to screen\n");
    write_str("time: measure the runtime of a command\n");
    write_str("run_fg: run a process in the foreground\n");
    write_str("run_bg: run a process in the background\n");
}

void kill(char *args) {
    write_str("kill\n");
}

void run_bg(char *args) {
    // ToDo: add core_id
    if(args == NULL) {
        printf("run_fg: provide a binary name\n");
        return;
    }

    domainid_t pid;
    aos_rpc_process_spawn(get_init_rpc(), args, 0, &pid);

}

void run_fg(char *args) {
    // ToDo: add core_id
    if(args == NULL) {
        printf("run_fg: provide a binary name\n");
        return;
    }

    domainid_t pid;
    aos_rpc_process_spawn(get_init_rpc(), args, 0, &pid);

    bool pid_still_exists = true;

    do{
        pid_still_exists = false;
        size_t pid_count;
        domainid_t *pids;
        errval_t  err = aos_rpc_process_get_all_pids(shell_state.init_rpc, &pids, &pid_count);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Something went wrong \n");
        }

        for (int i = 0; i < pid_count; i++) {
            if(pid == pids[i]){
                pid_still_exists = true;
            }
        }
        free(pids);
        thread_yield();
    } while (pid_still_exists);
}

/*
void spawn_hello(char **args) {
    abort();
    domainid_t pid;
    aos_rpc_process_spawn(get_init_rpc(), "hello", 0, &pid);
}
*/

void ps(char *args) {
    domainid_t *pids;
    size_t pid_count;
    aos_rpc_process_get_all_pids(get_init_rpc(), &pids, &pid_count);
    printf("pids count: %zu \n", pid_count);
    for (int i = 0; i < pid_count; i++) {
        printf("received pid: 0x%x\n", pids[i]);
    }
    free(pids);
}

void shell_exit(char *args) {
    shell_state.exit = true;
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

void echo(char *args) {
    if(args != NULL) {
        printf("%s\n", args);
    }
}