#ifndef _INIT_ENET_SERVICE_H
#define _INIT_ENET_SERVICE_H

#include <aos/aos.h>

#include "enet.h"

errval_t enet_service_init(struct enet_driver_state *st);

#endif