#ifndef _INIT_PROC_MGMT_H_
#define _INIT_PROC_MGMT_H_

#include <aos/aos.h>
#include <spawn/spawn.h>

errval_t setup_process(char *cmd, struct spawninfo *si, domainid_t *pid);

errval_t dispatch_process(struct spawninfo *si);

errval_t spawn_process(char *cmd, struct spawninfo *si, domainid_t *pid);

errval_t process_spawn_request(char *cmd, domainid_t *retpid);

errval_t process_get_all_pids(size_t *ret_nr_of_pids, domainid_t **ret_pids);

errval_t process_pid2name(domainid_t pid, char **retname);

errval_t process_aos_ump_bind_request(struct capref frame_cap);

errval_t process_write_char_request(char *buf);

errval_t process_read_char_request(char *c);

errval_t spawn_lpuart_driver(struct spawninfo **retsi);

errval_t spawn_sdhc_driver(struct spawninfo **retsi);

errval_t spawn_enet_driver(struct spawninfo **retsi);

#endif