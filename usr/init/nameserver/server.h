#ifndef NAMESERVER_SERVER_H
#define NAMESERVER_SERVER_H

#include <aos/aos.h>
#include <aos/aos_lmp.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_types.h>

errval_t aos_process_service_register(char *payload, size_t bytes);

#endif  // NAMESERVER_SERVER_H
