#include "helper.h"
#include <aos/aos_rpc.h>


errval_t write_str(char *str) {
    /**
     * Helper function to print. In contrast to printf(), this is not buffered
     */
    errval_t err = SYS_ERR_OK;
    for (int i = 0; i < strlen(str); ++i) {
        aos_rpc_serial_putchar(shell_state.serial_rpc, str[i]);
    }
    return err;
}

/**
 * Extracts the optional core number from the arguments, and spawns the requested process.
 * This assumes that no program is named '0', '1', '2', or '3'. An alternative would be to make
 * the core id mandatory or use a named argument.
 * @param args
 * @param pid
 * @return
 */
errval_t spawn_process(char *args, domainid_t *pid) {
    if(args == NULL) {
        printf("run_fg: provide a binary name\n");
        return SYS_ERR_NOT_IMPLEMENTED; // todo: better error
    }

    char *command = args;
    char *core = strtok(args, " ");
    errval_t  err;

    int c = 0;
    if(*core == '0' || *core == '1' || *core == '2' || *core == '3') {
        command = strtok(NULL, "");
        c = *core - '0';
        if(command == NULL) {
            printf("run_fg: provide a binary name\n");
            return SYS_ERR_NOT_IMPLEMENTED; // todo: better error;
        }
    }

    err = aos_rpc_process_spawn(get_init_rpc(), command, c, pid);
    if (err_pop(err) == SPAWN_ERR_FIND_MODULE) {
        printf("Could not find binary \"%s\"\n", args);
        return err;
    } else if (err_is_fail(err)) {
        printf("Failed to spawn process \"%s\"\n", args);
        return err;
    }

    return err;
}
