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