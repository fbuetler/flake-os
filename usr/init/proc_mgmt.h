#ifndef _INIT_PROC_MGMT_H_
#define _INIT_PROC_MGMT_H_

#include <aos/aos.h>
#include <spawn/spawn.h>

errval_t start_process(char *cmd, struct spawninfo *si, domainid_t *pid);

errval_t process_spawn_request(char *cmd, domainid_t *retpid);

errval_t process_get_all_pids(size_t *ret_nr_of_pids, domainid_t **ret_pids);

errval_t process_pid2name(domainid_t pid, char **retname);

errval_t process_ump_bind_request(struct capref frame_cap);

#endif