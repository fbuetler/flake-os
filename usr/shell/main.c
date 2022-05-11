#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <drivers/pl011.h>
#include <maps/qemu_map.h>
//#include <offsets.h>

int main(int argc, char *argv[])
{
    DEBUG_PRINTF("Shell Started\n");
    //lvaddr_t base = local_phys_to_mem(QEMU_UART_BASE);

    // map registers of pl011 uart driver

    struct capref devframe = (struct capref) {
        .cnode = cnode_arg,
        .slot = ARGCN_SLOT_DEVFRAME
    };

    void* vbase;
    errval_t err = paging_map_frame_attr(get_current_paging_state(), &vbase, PAGE_SIZE, devframe, VREGION_FLAGS_READ_WRITE_NOCACHE);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not map pl011 registers\n");
        return -1;
    }

    if((void*) vbase == NULL) {
        DEBUG_PRINTF("Could not map pl011 registers, region is empty \n");
        return -1;
    }
    struct pl011_s *s;
    lvaddr_t *base = (lvaddr_t *)vbase;
    pl011_init(&s, base);
    pl011_putchar(s, 'x');
}