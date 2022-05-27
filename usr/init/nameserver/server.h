#ifndef NAMESERVER_SERVER_H
#define NAMESERVER_SERVER_H

#include <aos/aos.h>
#include <aos/aos_lmp.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_types.h>
#include <aos/nameserver.h>

errval_t aos_process_service_register(char *payload, size_t bytes);
errval_t aos_process_service_lookup(char *payload, size_t bytes, service_info_t **retinfo);

#endif  // NAMESERVER_SERVER_H
