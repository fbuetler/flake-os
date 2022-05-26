/**
 * \file
 * \brief Barrelfish library initialization.
 */

/*
 * Copyright (c) 2007-2019, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/deferred.h>

#include "threads_priv.h"
#include "init.h"

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

void libc_exit(int);

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
    DEBUG_PRINTF("libc exit NYI!\n");
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {
    }
}

static void libc_assert(const char *expression, const char *file, const char *function,
                        int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf),
                   "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN, disp_name(), expression, function,
                   file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__)) static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if (len) {
        errval_t err = sys_print(buf, len);

        if (err_is_fail(err)) {
            return 0;
        }
    }

    return len;
}

__attribute__((__used__)) static size_t terminal_write(const char *buf, size_t len)
{
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();

    if (!rpc || init_domain) {
        return syscall_terminal_write(buf, len);
    } else {
        int i = 0;
        while (i++ < len) {
            aos_rpc_serial_putchar(rpc, *(buf++));
        }
    }
    return len;
}

__attribute__((__used__)) static size_t terminal_read(char *buf, size_t len)
{
    errval_t err;
    struct aos_rpc *rpc = get_init_rpc();
    if (1) {
        int i = 0;
        while (i++ < len) {
            err = sys_getchar(buf++);
            if (err_is_fail(err)) {
                return i - 1;
            }
        }
    } else {
        int i = 0;
        while (i++ < len) {
            err = aos_rpc_serial_getchar(rpc, (buf++));
            if (err_is_fail(err)) {
                return i - 1;
            }
        }
    }
    return len;
}


__attribute__((__used__)) static size_t dummy_terminal_read(char *buf, size_t len)
{
    DEBUG_PRINTF("Terminal read NYI!\n");
    return 0;
}

static struct aos_rpc rpc;
static struct aos_rpc mem_rpc;

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = dummy_terminal_read;
    _libc_terminal_write_func = syscall_terminal_write;
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */

    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}


/** \brief Initialise libbarrelfish.
 *
 * This runs on a thread in every domain, after the dispatcher is setup but
 * before main() runs.
 */
errval_t barrelfish_init_onthread(struct spawn_domain_params *params)
{
    errval_t err;

    // do we have an environment?
    if (params != NULL && params->envp[0] != NULL) {
        extern char **environ;
        environ = params->envp;
    }

    // Init default waitset for this dispatcher
    struct waitset *default_ws = get_default_waitset();
    waitset_init(default_ws);

    // Initialize ram_alloc state
    ram_alloc_init();
    /* All domains use smallcn to initialize */
    err = ram_alloc_set(ram_alloc_fixed);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    err = paging_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_INIT);
    }

    err = slot_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC_INIT);
    }

    err = morecore_init(BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MORECORE_INIT);
    }

    lmp_endpoint_init();

    // HINT: Use init_domain to check if we are the init domain.
    if (init_domain) {
        err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to retype self endpoint of init");
            return err_push(err, SPAWN_ERR_CREATE_SELFEP);
        }

        // setup endpoint of init
        err = aos_lmp_setup_local_chan(&init_spawninfo.lmp, cap_initep);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to setup local rpc channel for init");
            return err;
        }
        // setup endpoint for memory requests
        err = aos_lmp_setup_local_chan(&init_spawninfo.mem_lmp, cap_initmemep);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to setup local mem rpc channel for init");
            return err;
        }
        return SYS_ERR_OK;
    }

    rpc.is_lmp = mem_rpc.is_lmp = true;
    struct aos_lmp *lmp = &rpc.u.lmp;
    struct aos_lmp *mem_lmp = &mem_rpc.u.lmp;

    err = aos_lmp_init_static(mem_lmp, AOS_RPC_MEMORY_CHANNEL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init mem rpc");
        return err_push(err, LIB_ERR_LMP_INIT_STATIC);
    }

    err = aos_lmp_initiate_handshake(mem_lmp);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to perform handshake over memory channel");
        return err_push(err, LIB_ERR_LMP_INIT_HANDSHAKE);
    }
    // reset the RAM allocator to use ram_alloc_remote
    set_init_mem_rpc(&mem_rpc);
    ram_alloc_set(NULL);

    // we do not register an event handler for the memory channel

    err = aos_lmp_init_static(lmp, AOS_RPC_BASE_CHANNEL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init rpc");
        return err_push(err, LIB_ERR_LMP_INIT);
    }

    err = aos_lmp_initiate_handshake(lmp);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to perform handshake over init channel");
        return err_push(err, LIB_ERR_LMP_INIT_HANDSHAKE);
    }

    err = aos_lmp_register_recv(lmp, aos_lmp_event_handler);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register init channel to event handler");
        return err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
    }

    set_init_rpc(&rpc);

    return SYS_ERR_OK;
}


/**
 *  \brief Initialise libbarrelfish, while disabled.
 *
 * This runs on the dispatcher's stack, while disabled, before the dispatcher is
 * setup. We can't call anything that needs to be enabled (ie. cap invocations)
 * or uses threads. This is called from crt0.
 */
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg);
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg)
{
    init_domain = init_dom_arg;
    disp_init_disabled(handle);
    thread_init_disabled(handle, init_dom_arg);
}
