#ifndef _INIT_CORE_MGMT_H_
#define _INIT_CORE_MGMT_H_

#include <aos/aos.h>

errval_t boot_core(coreid_t core_id);

errval_t init_app_core(void);

errval_t cpu_off(void);

errval_t cpu_on(hwid_t core_id);

#endif