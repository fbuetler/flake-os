#include <spawn/spawn.h>

#ifndef _SERIALIO_H
#define _SERIALIO_H

enum seriaoio_reponse_type {
    SERIAL_IO_NO_DATA,
    SERIAL_IO_SUCCESS
};

struct serialio_response {
    enum seriaoio_reponse_type response_type;
    char c;
};

errval_t init_serial_server(struct spawninfo *si);
errval_t serial_get_char(struct aos_lmp *lmp, struct serialio_response *serial_response);
#endif
