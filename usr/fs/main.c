/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/deferred.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>

void *sd_mem_base;

static inline lpaddr_t shdc_get_phys_addr(void *addr){
    size_t offset = (size_t)addr - (size_t)sd_mem_base;

    size_t phys_base = IMX8X_SDHC2_BASE;
    return (lpaddr_t)(phys_base + offset);
}


static errval_t setup_read_buffer(size_t bytes, lpaddr_t *phys_base, void **virt_base) {
    // get a frame first
    struct capref cap;
    errval_t err = frame_alloc(&cap, bytes, NULL);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "frame_alloc");
        return err;
    }

    // map it

    // TODO is this really nocache?
    err = paging_map_frame_attr(get_current_paging_state(), virt_base, bytes, cap,
                                    VREGION_FLAGS_READ_WRITE_NOCACHE);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "paging_map_frame_attr");
        return err;
    } 

    if(*virt_base == NULL){
        DEBUG_PRINTF("virt_base is NULL\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    err = get_phys_addr(cap, (genpaddr_t *)(phys_base), NULL);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "get_phys_addr");
        return err;
    }

    return SYS_ERR_OK;

}

int main(int argc, char *argv[])
{
    struct sdhc_s *sd;
    
    struct capref devframe_cap = (struct capref) {
        .cnode = cnode_arg,
        .slot = ARGCN_SLOT_DEVFRAME,
    };

    size_t devframe_bytes;
    genpaddr_t devframe_base;
    errval_t err = get_phys_addr(devframe_cap, &devframe_base, &devframe_bytes);

    assert(err_is_ok(err));

    err = paging_map_frame_attr(get_current_paging_state(), &sd_mem_base,
                                devframe_bytes, devframe_cap,
                                VREGION_FLAGS_READ_WRITE_NOCACHE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map dev frame");
        return err;
    }
    if ((void *)sd_mem_base == NULL) {
        USER_PANIC("FS: No register region mapped \n");
    }

    DEBUG_PRINTF("initializing sdhc... \n");
    err = sdhc_init(&sd, sd_mem_base);
    DEBUG_PRINTF("sdhc initialized\n");


    DEBUG_PRINTF("setting up read buffer...\n");
    lpaddr_t lpbuf;
    void *vbuf;
    err = setup_read_buffer(BASE_PAGE_SIZE, &lpbuf, &vbuf);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "setup_read_buffer");
        return err;
    }
    DEBUG_PRINTF("read buffer has been set up\n");


    /*
        READ A BLOCK


0x000000: fab800108ed0bc00b0b800008ed88ec0
0x000010: fbbe007cbf0006b90002f3a4ea210600
0x000020: 00bebe073804750b83c61081fefe0775
0x000030: f3eb16b402b001bb007cb2808a74018b
0x000040: 4c02cd13ea007c0000ebfe0000000000



0000000 58eb 6d90 666b 2e73 6166 0074 0802 0020
0000010 0002 0000 f800 0000 0020 0040 0800 0000
0000020 c000 01da 7678 0000 0000 0000 0002 0000
0000030 0001 0006 0000 0000 0000 0000 0000 0000
0000040 0080 fa29 5802 4ee4 204f 414e 454d 2020
0000050 2020 4146 3354 2032 2020 1f0e 77be ac7c
0000060 c022 0b74 b456 bb0e 0007 10cd eb5e 32f0
0000070 cde4 cd16 eb19 54fe 6968 2073 7369 6e20
0000080 746f 6120 6220 6f6f 6174 6c62 2065 6964
0000090 6b73 202e 5020 656c 7361 2065 6e69 6573
00000a0 7472 6120 6220 6f6f 6174 6c62 2065 6c66
00000b0 706f 7970 6120 646e 0a0d 7270 7365 2073
00000c0 6e61 2079 656b 2079 6f74 7420 7972 6120
00000d0 6167 6e69 2e20 2e2e 0d20 000a 0000 0000
00000e0 0000 0000 0000 0000 0000 0000 0000 0000



EB58906D6B66732E
6661740002082000
0200000000F80000
2000400000080000
00C0DA0178760000
0000000002000000
0100060000000000
0000000000000000
800029FA0258E44E
4F204E414D452020
2020464154333220
20200E1FBE777CAC
22C0740B56B40EBB
0700CD105EEBF032
E4CD16CD19EBFE54
686973206973206E
6F74206120626F6F
7461626C65206469
736B2E2020506C65
61736520696E7365
7274206120626F6F
7461626C6520666C
6F70707920616E64
0D0A707265737320
616E79206B657920
746F207472792061
6761696E202E2E2E
200D0A0000000000
0000000000000000
*
00000000000055AA
5252614100000000
0000000000000000
*
0000000072724161
5D3A3B0002000000
0000000000000000
00000000000055AA
0000000000000000
*
EB58906D6B66732E
6661740002082000
0200000000F80000
2000400000080000
00C0DA0178760000
0000000002000000
0100060000000000
0000000000000000
800029FA0258E44E
4F204E414D452020
2020464154333220
20200E1FBE777CAC
22C0740B56B40EBB
0700CD105EEBF032
E4CD16CD19EBFE54
686973206973206E
6F74206120626F6F
7461626C65206469
736B2E2020506C65
61736520696E7365
7274206120626F6F
7461626C6520666C
6F70707920616E64
0D0A707265737320
616E79206B657920
746F207472792061
6761696E202E2E2E
200D0A0000000000
0000000000000000
*
00000000000055AA
5252614100000000
0000000000000000
*
0000000072724161
5D3A3B0002000000
0000000000000000
00000000000055AA
0000000000000000
*
F8FFFF0FFFFFFF0F
F8FFFF0F00000000
0000000000000000
*

    */

    for(int i = 0; i < 1000; i++){
        ((char *)vbuf)[i] = (i%2) ? 0xff : 0xee;
    }

    dmb();

    err = sdhc_read_block(sd, 0, lpbuf);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "sdhc_read_block");
        return err;
    }

    // print 512 bytes
    char *buf = (char *)vbuf;
    for (int i = 0; i < 512; i++) {
        if (i % 16 == 0) {
            printf("\n");
            printf("0x%06lx: ", i);
        }
        printf("%02x", buf[i]);
    }
    printf("\n");
    
    assert(err_is_ok(err));

    return EXIT_SUCCESS;
}
