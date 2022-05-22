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
    write_str("run_fg: TODO\n");
    write_str("run_bg: TODO\n");
}

void kill(char *args) {
    write_str("kill\n");
}

void run_bg(char *args) {

}

void run_fg(char *args) {
    DEBUG_PRINTF("spawning hello in the foreground \n");
    domainid_t pid;
    aos_rpc_process_spawn(get_init_rpc(), "hello", 0, &pid);

    DEBUG_PRINTF("busy looping until hello terminates...\n");

    printf("waiting for pid: %d \n \n", pid);
    //DEBUG_PRINTF("killing hello \n");
    //aos_rpc_kill_process(shell_state.init_rpc, &pid);
    //DEBUG_PRINTF("returned from killing hello \n");
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
            //printf("pid: %d \n", pids[i]);
            if(pid == pids[i]){
                pid_still_exists = true;
            }
        }
        //thread_yield();
    } while (pid_still_exists);
    DEBUG_PRINTF("hello terminated, shell continues...\n");
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
    DEBUG_PRINTF("pids count: %zu \n", pid_count);
    for (int i = 0; i < pid_count; i++) {
        DEBUG_PRINTF("received pid: 0x%x\n", pids[i]);
    }
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