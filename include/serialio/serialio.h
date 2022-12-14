#include <spawn/spawn.h>

#ifndef _SERIALIO_H
#define _SERIALIO_H

enum seriaoio_reponse_type {
    SERIAL_IO_NO_DATA,
    SERIAL_IO_SUCCESS
};

enum serialio_type {
    UART_QEMU,
    UART_TORADEX
};

struct serialio_response {
    enum seriaoio_reponse_type response_type;
    char c;
};

errval_t init_serial_server(enum serialio_type uart_type);
errval_t serial_get_char(struct aos_lmp *lmp, struct serialio_response *serial_response);
errval_t serial_put_char(struct aos_lmp *lmp, const char *c);

#endif
