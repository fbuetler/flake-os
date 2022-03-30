/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>


errval_t aos_rpc_init_chan_to_child(struct aos_rpc *init_rpc, struct aos_rpc *child_rpc) {
	errval_t err;

	// setup channel of memeater
	lmp_chan_init(&child_rpc->chan);
   
	child_rpc->chan.endpoint = init_rpc->chan.endpoint;

	struct capref memeater_endpoint_cap;
	err = slot_alloc(&memeater_endpoint_cap);
	if (err_is_fail(err)) {
		DEBUG_PRINTF("Failed to allocate slot for memeater endpoint\n");
	}
	assert(err_is_ok(err));

	 while (1) {
		struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;

		lmp_endpoint_set_recv_slot(child_rpc->chan.endpoint, memeater_endpoint_cap);
		err = lmp_endpoint_recv(child_rpc->chan.endpoint, &recv_msg.buf,
								&memeater_endpoint_cap);
		if (err_is_fail(err)){
			if(err == LIB_ERR_NO_LMP_MSG || lmp_err_is_transient(err)) {
				//DEBUG_ERR(err, "no lmp msg, or is transiend: continue! \n");
				continue;
			} else {
				DEBUG_ERR(err, "loop in main, !err_is_transient \n");
				assert(0);
			}
		} else {
			// TODO caution: si is on stack & memeater_endpoint_cap is on stack
			//si.endpoint = &memeater_endpoint_cap;
			break;
		}
	}

	child_rpc->chan.local_cap = cap_initep;
	child_rpc->chan.remote_cap = memeater_endpoint_cap;

	printf("init local\n");
	char buf0[256];
	debug_print_cap_at_capref(buf0, 256, child_rpc->chan.local_cap);
	debug_printf("%.*s\n", 256, buf0);

	printf("init remote\n");
	char buf1[256];
	debug_print_cap_at_capref(buf1, 256, child_rpc->chan.remote_cap);
	debug_printf("%.*s\n", 256, buf1);

	err = lmp_chan_send0(&child_rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "failed to send acknowledgement");
	}
	assert(err_is_ok(err));

	return SYS_ERR_OK;
}

/**
 *  \brief Initialize an aos_rpc struct. Sets up channel to remote endpoint (init)
 * 
 *  \param aos_rpc The aos_rpc struct to initialize.
 * 
 **/
errval_t aos_rpc_init(struct aos_rpc *aos_rpc){
	errval_t err;

    // TODO MILESTONE 3: register ourselves with init
    /* allocate lmp channel structure */

    /* create local endpoint */
    lmp_chan_init(&aos_rpc->chan);

    struct lmp_endpoint *ep = malloc(sizeof(struct lmp_endpoint));
    assert(ep);
 
    aos_rpc->chan.endpoint = ep;
    err = endpoint_create(8, &aos_rpc->chan.local_cap, &aos_rpc->chan.endpoint);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not create endpoint in child \n");
        return err;
    }

    /* set remote endpoint to init's endpoint */
    aos_rpc->chan.remote_cap = cap_initep;
    set_init_rpc(aos_rpc);

    /* set receive handler */
    err = lmp_chan_register_recv(&aos_rpc->chan, get_default_waitset(),
                                 MKCLOSURE(aos_handshake_recv_closure, &aos_rpc->chan));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not register recv handler in child \n");
        return err;
    }

    /* send local ep to init */
    err = lmp_chan_send0(&aos_rpc->chan, LMP_SEND_FLAGS_DEFAULT, aos_rpc->chan.local_cap);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Could not send child endpoint cap to init\n");
        return err;
    }

    /* wait for init to acknowledge receiving the endpoint */
    while(!lmp_chan_can_recv(&aos_rpc->chan)) {
        err = event_dispatch(get_default_waitset());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    };

    printf("memeater local\n");
    char buf0[256];
    debug_print_cap_at_capref(buf0, 256, aos_rpc->chan.local_cap);
    debug_printf("%.*s\n", 256, buf0);

    printf("memeater remote\n");
    char buf1[256];
    debug_print_cap_at_capref(buf1, 256, aos_rpc->chan.remote_cap);
    debug_printf("%.*s\n", 256, buf1);

    /* initialize init RPC client with lmp channel */

    /* set init RPC client in our program state */

    /* TODO MILESTONE 3: now we should have a channel with init set up and can
     * use it for the ram allocator */

    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here

	return SYS_ERR_OK;
}

errval_t
aos_rpc_send_number(struct aos_rpc *child_rpc, uintptr_t num) {
	// TODO: implement functionality to send a number over the channel
	// given channel and wait until the ack gets returned.
	printf("Inside RPC_SEND_NUMBER \n"); 

	struct aos_rpc_msg *msg = malloc(sizeof(struct aos_rpc_msg) + sizeof(num));

	msg->header_size = sizeof(struct aos_rpc_msg);
	msg->payload_size = sizeof(num);
	msg->message_type = SendNumber;
	msg->payload[0] = num;

	errval_t err = lmp_chan_send(&child_rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, 4, num, 0, 0, 0);
	if(err_is_fail(err)) {
		DEBUG_ERR(err, "Could not send number\n");
		return AOS_ERR_LMP_SEND_FAILURE;
	}

	return SYS_ERR_OK;
}

errval_t
aos_rpc_send_string(struct aos_rpc *child_rpc, const char *string) {
	// TODO: implement functionality to send a string over the given channel
	// and wait for a response.

	printf("Inside sending string \n"); 
	errval_t err;

	struct aos_rpc_msg *msg = malloc(sizeof(struct aos_rpc_msg) + strlen(string));

	msg->header_size = sizeof(struct aos_rpc_msg);
	msg->payload_size = strlen(string);
	msg->message_type = SendString;
	strncpy(msg->payload, string, strlen(string));

	int total_size = msg->header_size + msg->payload_size;
	int transfered_size = 0;

	uint64_t * buf = (uint64_t*) msg;

	while(transfered_size < total_size) {
		int remaining_size = total_size - transfered_size;
		if(remaining_size >=  4*sizeof(uint64_t)) {
			err = lmp_chan_send(&child_rpc->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, 4, buf[0], buf[1], buf[2], buf[3]);

			if(err_is_fail(err)) {
				DEBUG_ERR(err, "Failed sending stream! \n");
				return AOS_ERR_LMP_SEND_FAILURE;
			}

			transfered_size += 4*sizeof(uint64_t);
		}

	}
	return SYS_ERR_OK;
}

/**
 * \brief Receive a number from the given channel.
 * 
 * After you obtained a new frame capability, you can use your paging infrastructure from the
 * previous milestone to map it and access the memory on it.
 */
errval_t
aos_rpc_get_ram_cap(struct aos_rpc *child_rpc, size_t bytes, size_t alignment,
					struct capref *ret_cap, size_t *ret_bytes) {
	// TODO: implement functionality to request a RAM capability over the
	// given channel and wait until it is delivered.
	return SYS_ERR_OK;
}


errval_t
aos_rpc_serial_getchar(struct aos_rpc *child_rpc, char *retc) {
	// TODO implement functionality to request a character from
	// the serial driver.
	return SYS_ERR_OK;
}


errval_t
aos_rpc_serial_putchar(struct aos_rpc *child_rpc, char c) {
	// TODO implement functionality to send a character to the
	// serial port.
	return SYS_ERR_OK;
}

errval_t
aos_rpc_process_spawn(struct aos_rpc *child_rpc, char *cmdline,
					  coreid_t core, domainid_t *newpid) {
	// TODO (M5): implement spawn new process child_rpc
	return SYS_ERR_OK;
}



errval_t
aos_rpc_process_get_name(struct aos_rpc *child_rpc, domainid_t pid, char **name) {
	// TODO (M5): implement name lookup for process given a process id
	return SYS_ERR_OK;
}


errval_t
aos_rpc_process_get_all_pids(struct aos_rpc *child_rpc, domainid_t **pids,
							 size_t *pid_count) {
	// TODO (M5): implement process id discovery
	return SYS_ERR_OK;
}

void aos_handshake_recv_closure (void *arg) {
	errval_t err;

	printf("Inside handshake recv closure\n");

	struct lmp_chan *lc = arg;
	struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
	struct capref cap;

	err = lmp_chan_recv(lc, &recv_msg, &cap);
	if (err_is_fail(err) && lmp_err_is_transient(err)) {
		DEBUG_ERR(err, "lmp transient error received");
		lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(aos_handshake_recv_closure, lc));
		return;
	} else if (err_is_fail(err)) {
		DEBUG_ERR(err, "failed to receive message");
		// TODO this needs to be handled properly for handshake!
		// e.g.: terminate child process? retry?
		return;
	}
	debug_printf("msg length: %d\n", recv_msg.buf.msglen);

	lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(aos_handshake_recv_closure, lc));
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
	return get_init_rpc();	
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
	//TODO: Return channel to talk to memory server process (or whoever
	//implements memory server functionality)
	return get_init_rpc();	
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
	//TODO: Return channel to talk to process server process (or whoever
	//implements process server functionality)
	debug_printf("aos_rpc_get_process_channel NYI\n");
	return NULL;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
	//TODO: Return channel to talk to serial driver/terminal process (whoever
	//implements print/read functionality)
	debug_printf("aos_rpc_get_serial_channel NYI\n");
	return NULL;
}

