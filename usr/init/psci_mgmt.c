#include <stdio.h>
#include <stdlib.h>

#include "psci_mgmt.h"

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/kernel_cap_invocations.h>

errval_t cpu_off(void)
{
    DEBUG_PRINTF("turning CPU OFF\n")
    errval_t err;
    err = invoke_monitor_cpu_off();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to turn cpu off");
        return err;
    }
    DEBUG_PRINTF("turned CPU OFF\n")

    return SYS_ERR_OK;
}

errval_t cpu_on(void)
{
    DEBUG_PRINTF("turning CPU ON\n")
    // errval_t err;
    // err = invoke_monitor_cpu_on();
    // if (err_is_fail(err)) {
    //     DEBUG_ERR(err, "failed to turn cpu on");
    //     return err;
    // }
    DEBUG_PRINTF("turned CPU ON\n")

    return SYS_ERR_OK;
}