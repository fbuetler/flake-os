#ifndef _INIT_PROC_MGMT_H_
#define _INIT_PROC_MGMT_H_

#include <aos/aos.h>
#include <spawn/spawn.h>

errval_t start_process(char *cmd, struct spawninfo *si, domainid_t *pid);

#endif