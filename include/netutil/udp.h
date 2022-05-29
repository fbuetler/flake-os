#ifndef _UDP_H_
#define _UDP_H_

#include <netutil/ip.h>

// #define UDP_ECHO 1
// #define UDP_HACK 1
// #define UDP_ECHO_SERVER 1

// #define UDP_DEBUG_OPTION 1

#if defined(UDP_DEBUG_OPTION)
#    define UDP_DEBUG(x...) debug_printf("[udp] " x);
#else
#    define UDP_DEBUG(fmt, ...) ((void)0)
#endif

/**
 * UDP header
 */
#define UDP_HLEN 8
struct udp_hdr {
    uint16_t src;
    uint16_t dest; /* src/dest UDP ports */
    uint16_t len;
    uint16_t chksum;
} __attribute__((__packed__));


#endif
