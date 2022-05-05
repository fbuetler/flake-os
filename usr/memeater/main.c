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
#include <aos/rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>

static struct rpc *init_rpc, *mem_rpc;

const char *str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
                  "sed do eiusmod tempor incididunt ut labore et dolore magna "
                  "aliqua. Ut enim ad minim veniam, quis nostrud exercitation "
                  "ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                  "Duis aute irure dolor in reprehenderit in voluptate velit "
                  "esse cillum dolore eu fugiat nulla pariatur. Excepteur sint "
                  "occaecat cupidatat non proident, sunt in culpa qui officia "
                  "deserunt mollit anim id est laborum.";

static errval_t request_and_map_memory(void)
{
    errval_t err;

    size_t bytes;
    struct frame_identity id;
    DEBUG_PRINTF("testing memory server...\n");

    struct paging_state *pstate = get_current_paging_state();

    DEBUG_PRINTF("obtaining cap of %" PRIu32 " bytes...\n", BASE_PAGE_SIZE);

  
    struct capref cap1;
    err = aos_rpc_get_ram_cap(mem_rpc, BASE_PAGE_SIZE, BASE_PAGE_SIZE, &cap1, &bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not get BASE_PAGE_SIZE cap\n");
        return err;
    }

    struct capref cap1_frame;
    err = slot_alloc(&cap1_frame);
    assert(err_is_ok(err));

    DEBUG_PRINTF("Retype to frame \n");

    err = cap_retype(cap1_frame, cap1, 0, ObjType_Frame, BASE_PAGE_SIZE, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not retype RAM cap to frame cap\n");
        return err;
    }

    err = frame_identify(cap1_frame, &id);
    assert(err_is_ok(err));

    DEBUG_PRINTF("Mapping frame \n");
    void *buf1;
    err = paging_map_frame(pstate, &buf1, BASE_PAGE_SIZE, cap1_frame);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not get BASE_PAGE_SIZE cap\n");
        return err;
    }

    DEBUG_PRINTF("got frame: 0x%" PRIxGENPADDR " mapped at %p\n", id.base, buf1);

    memset(buf1, 0x00, BASE_PAGE_SIZE);

    DEBUG_PRINTF("obtaining cap of %" PRIu32 " bytes using frame alloc...\n",
                 LARGE_PAGE_SIZE);

    struct capref cap2;
    err = frame_alloc(&cap2, LARGE_PAGE_SIZE, &bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not get BASE_PAGE_SIZE cap\n");
        return err;
    }

    err = frame_identify(cap2, &id);
    assert(err_is_ok(err));

    void *buf2;
    err = paging_map_frame(pstate, &buf2, LARGE_PAGE_SIZE, cap2);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not get BASE_PAGE_SIZE cap\n");
        return err;
    }

    DEBUG_PRINTF("got frame: 0x%" PRIxGENPADDR " mapped at %p\n", id.base, buf1);

    DEBUG_PRINTF("performing memset.\n");
    memset(buf2, 0x00, LARGE_PAGE_SIZE);

    return SYS_ERR_OK;
}

static errval_t test_basic_rpc(void)
{
    errval_t err;

    DEBUG_PRINTF("RPC: testing basic RPCs...\n");

    DEBUG_PRINTF("RPC: sending number...\n");
    err = aos_rpc_send_number(init_rpc, 42);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not send a string\n");
        return err;
    }

    DEBUG_PRINTF("RPC: sending small string...\n");
    err = aos_rpc_send_string(init_rpc, "Hello init");
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not send a string\n");
        return err;
    }

    DEBUG_PRINTF("RPC: sending large string...\n");
    err = aos_rpc_send_string(init_rpc, str);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not send a string\n");
        return err;
    }

    DEBUG_PRINTF("RPC: testing basic RPCs. SUCCESS\n");

    return SYS_ERR_OK;
}


int main(int argc, char *argv[])
{
    errval_t err = SYS_ERR_OK;

    DEBUG_PRINTF("memeater started....\n");

    init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        USER_PANIC_ERR(err, "init RPC channel NULL?\n");
    }

    mem_rpc = aos_rpc_get_memory_channel();
    if (!mem_rpc) {
        USER_PANIC_ERR(err, "memory RPC channel NULL?\n");
    }

    err = test_basic_rpc();
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failure in testing basic RPC\n");
    }

    err = request_and_map_memory();
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "could not request and map memory\n");
    }

    DEBUG_PRINTF("spawning hello\n");
    domainid_t pid;
    err = aos_rpc_process_spawn(init_rpc, "hello", !disp_get_current_core_id(), &pid);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "could not spawn process\n");
    }
/*
    
    DEBUG_PRINTF("attempting pid2name...\n");
    char *name;
    aos_rpc_process_get_name(init_rpc, pid, &name);
    DEBUG_PRINTF("received pid2name result of pid 0x%lx: %s\n", pid, name);
*/


    size_t pid_count;
    domainid_t *pids;
    aos_rpc_process_get_all_pids(init_rpc, &pids, &pid_count);

    DEBUG_PRINTF("PID count: %d\n", pid_count);
    
    for(int i = 0; i < pid_count; i++){
        DEBUG_PRINTF("received pid: 0x%lx\n", pids[i]);
    }

    return 0;

    char c;
    // aos_rpc_serial_putchar(init_rpc, c);
    DEBUG_PRINTF("enter a char: \n");
    err = aos_rpc_serial_getchar(init_rpc, &c);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to get char");
    }
    DEBUG_PRINTF("get char: %c\n", c);

    /* test printf functionality */
    DEBUG_PRINTF("testing terminal printf function...\n");

    printf("Hello world using terminal service\n");
    DEBUG_PRINTF("memeater terminated....\n");

    return EXIT_SUCCESS;
}
