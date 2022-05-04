#include <aos/ump_chan.h>
#include <aos/aos_rpc.h>

void ump_debug_print(struct ump_chan *ump)
{
    DEBUG_PRINTF("Send:\nbase: 0x%lx\nnext: %d\n", ump->send_base, ump->send_next);
    DEBUG_PRINTF("SEND MEMORY DUMP:\n");
    size_t show_cache_lines = 3;
    for (int i = 0; i < show_cache_lines * 8; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, ump->send_base - 8 + i,
                     *(ump->send_base - 8 + i));
    }

    DEBUG_PRINTF("Receive:\nbase: 0x%lx\nnext: %d\n", ump->recv_base, ump->recv_next);
    DEBUG_PRINTF("RECEIVE MEMORY DUMP:\n");
    for (int i = 0; i < show_cache_lines * 8; i++) {
        DEBUG_PRINTF("%d: [0x%lx, 0x%lx]\n", i, ump->recv_base - 8 + i,
                     *(ump->recv_base - 8 + i));
    }
}

errval_t ump_initialize(struct ump_chan *ump, void *shared_mem, bool is_primary)
{
    thread_mutex_init(&ump->chan_lock);
    void *send_mem;
    void *recv_mem;
    if (is_primary) {
        send_mem = shared_mem;
        recv_mem = shared_mem + UMP_SECTION_BYTES;
    } else {
        send_mem = shared_mem + UMP_SECTION_BYTES;
        recv_mem = shared_mem;
    }

    ump->send_base = send_mem + UMP_MESSAGES_OFFSET;
    ump->send_next = 0;

    ump->recv_base = recv_mem + UMP_MESSAGES_OFFSET;
    ump->recv_next = 0;

    // DEBUG_PRINTF("Shared memory:\nsend: 0x%lx\nreceive: 0x%lx\n", send_mem, recv_mem);
    // genpaddr_t paddr;
    // paging_vaddr_to_paddr(get_current_paging_state(), (genvaddr_t)ump->send_base,
    // &paddr); DEBUG_PRINTF("Physical frame base: 0x%lx\n", paddr);

    return SYS_ERR_OK;
}

/**
 * Populate ump_msg struct on the stack
 */
static void ump_create_msg(struct ump_msg *msg, ump_msg_type type, char *payload,
                           size_t len, bool is_last)
{
    msg->header.msg_state = UmpMessageCreated;
    msg->header.msg_type = type;
    msg->header.last = is_last;
    msg->header.len = len;
    memcpy(msg->payload, payload, len);
}

static errval_t ump_send_msg(struct ump_chan *ump, struct ump_msg *msg)
{
    errval_t err;
    struct ump_msg *entry = (struct ump_msg *)ump->send_base + ump->send_next;
    volatile ump_msg_state *state = &entry->header.msg_state;

    DEBUG_PRINTF("sending UMP msg with type: %d \n", msg->header.msg_type);
    if (*state == UmpMessageSent) {
        err = LIB_ERR_UMP_CHAN_FULL;
        DEBUG_ERR(err, "send queue is full");
        return err;
    }

    dmb();  // ensure that we checked the above condition before copying

    memcpy(entry, msg, UMP_MSG_BYTES);

    dmb();  // ensure that the message is written to memory before logically mark it as sent

    entry->header.msg_state = UmpMessageSent;
    ump->send_next = (ump->send_next + 1) % UMP_MESSAGES_ENTRIES;

    // no barrier needed as the receiving side has a memory barrier after the check of the
    // message state. This already ensures that the message is not read before the state
    // has been successfully checked

    return SYS_ERR_OK;
}

errval_t ump_send(struct ump_chan *ump, ump_msg_type type, char *payload, size_t len)
{
    errval_t err;
    size_t offset = 0;
    /*
    DEBUG_PRINTF("Before lock in ump_send \n");
    thread_mutex_lock_nested(&chan->chan_lock);
    DEBUG_PRINTF("Acquired lock in ump_send \n");
    */
    if (len > UMP_MSG_MAX_BYTES) {
        err = LIB_ERR_UMP_SEND;
        DEBUG_ERR(err, "Message size exceeded max allowed size");
        return err;
    }

    struct ump_msg msg;
    while (offset < len) {
        size_t current_payload_len = MIN(len - offset, UMP_MSG_PAYLOAD_BYTES);
        size_t current_offset = offset;
        offset += current_payload_len;

        ump_create_msg(&msg, type, payload + current_offset, current_payload_len,
                       offset >= len);

        err = ump_send_msg(ump, &msg);
        if (err_is_fail(err)) {
            thread_mutex_unlock(&ump->chan_lock);
            DEBUG_ERR(err, "Failed to send message");
            err = err_push(err, LIB_ERR_UMP_SEND);
            return err;
        }
    }

    return SYS_ERR_OK;
}

static errval_t ump_receive_msg(struct ump_chan *ump, struct ump_msg *msg)
{
    // ump_debug_print(ump);


    struct ump_msg *entry = (struct ump_msg *)ump->recv_base + ump->recv_next;
    volatile ump_msg_state *state = &entry->header.msg_state;

    while (*state != UmpMessageSent) {
        // spin, cause it's cheap (L1 ftw!)
    }

    // This barrier does not need to be inside the polling loop as the state enum is
    // volatile. Further, the sending side has a data barrier before setting the correct
    // state. Therefore, the only memory instruction between the barrier on the sending
    // side and the polling loop reading that the state is UmpMessageSent is the sending
    // side writing UmpMessageSent to the cache line.
    dmb();  // ensure that we checked the above condition before copying

    assert(sizeof(struct ump_msg) == UMP_MSG_BYTES);
    memcpy(msg, entry, UMP_MSG_BYTES);

    dmb();  // ensure that the message is received before we mark it logically as received

    entry->header.msg_state = UmpMessageReceived;
    ump->recv_next = (ump->recv_next + 1) % UMP_MESSAGES_ENTRIES;

    // no barrier needed, as the sending side has a memory barrier after its check of the
    // message state


    return SYS_ERR_OK;
}

errval_t ump_receive(struct ump_chan *ump, ump_msg_type *rettype, char **retpayload,
                     size_t *retlen)
{
    // thread_mutex_lock_nested(&ump->chan_lock);
    errval_t err;

    size_t offset = 0;
    char *tmp_payload = malloc(UMP_MSG_MAX_BYTES);

    ump_msg_type msg_type;
    bool is_last = false;
    while (!is_last) {
        struct ump_msg msg;
        err = ump_receive_msg(ump, &msg);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to receive message");
            return err_push(err, LIB_ERR_UMP_RECV);
        }

        memcpy(tmp_payload + offset, &msg.payload, msg.header.len);

        offset += msg.header.len;
        is_last = msg.header.last;
        msg_type = msg.header.msg_type;
    }

    char *payload = malloc(offset);
    memcpy(payload, tmp_payload, offset);
    free(tmp_payload);

    *rettype = msg_type;
    *retpayload = payload;
    *retlen = offset;

    return SYS_ERR_OK;
}


errval_t ump_bind(struct aos_rpc *rpc, struct ump_chan *ump, struct ump_chan **sump, coreid_t core, enum aos_rpc_service service){
    // 1. The client allocates and maps a region of shared memory (the cframe in Figure 8.11.)
    struct capref cframe_cap;

    errval_t err = ump_create_server_chan(&cframe_cap, ump);
    assert(err_is_ok(err));

    // 2. The client calls its local monitor with a capability to this frame, and the identifier of the server it wants to connect to.
    // + 3. The client’s monitor figures out which monitor is on the same core as the server, and forwards the request to it.

    size_t payload_size = sizeof(coreid_t);
    char msg_buf[AOS_RPC_MSG_SIZE(payload_size)];
    struct aos_rpc_msg *msg;
    err = aos_rpc_create_msg_no_pagefault(&msg, UmpBindRequest, payload_size, &core, cframe_cap, (struct aos_rpc_msg*)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    }

   // inside RPC call: 4. The server’s monitor calls the server, giving it the client’s cframe.
    err = aos_rpc_call(rpc, msg, false);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed to call aos_rpc_call");
        return err;
    }

    // 5. Assuming the server decides to accept the connection, it allocates another region (the sframe) and returns this back to its local monitor
    // 6. The server’s monitor returns the sframe capability back to the client via the client’s local monitor.
    struct capref sframe_cap = msg->cap;

    if(capcmp(sframe_cap, NULL_CAP)){
        //err = LIB_ERR_RPC_INVALID_CAP;
        err = LIB_ERR_BIND_UMP_REQ;
        DEBUG_ERR(err, "failed to get sframe cap");
        return err;
    }

    struct frame_identity sframe_id;
    err = frame_identify(sframe_cap, &sframe_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to identify frame");
        return err;
    }
    
    // 7. The client maps the server’s region, and both sides are now ready to go. 
    void *s_urpc;
    err = paging_map_frame_complete(get_current_paging_state(), &s_urpc, sframe_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map urpc frame");
    }

    err = ump_initialize(*sump, s_urpc, false);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}


errval_t  ump_create_server_chan(struct capref *frame_cap, struct ump_chan *ump){
    DEBUG_PRINTF("creating UMP server chan\n");
    size_t allocated_bytes;
    errval_t err = frame_alloc(frame_cap, BASE_PAGE_SIZE, &allocated_bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate frame");
        return err;
    }

    if (allocated_bytes != BASE_PAGE_SIZE) {
        err = LIB_ERR_FRAME_ALLOC;
        DEBUG_ERR(err, "failed to allocate frame of the requested size");
        return err;
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(*frame_cap, &urpc_frame_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to identify frame");
        return err;
    }

    void *urpc;
    err = paging_map_frame_complete(get_current_paging_state(), &urpc, *frame_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map urpc frame");
        return err;
    }

    // init channel
    err = ump_initialize(ump, urpc, true);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed to initialize channel");
        return err;
    }


    DEBUG_PRINTF("ump server chan created!\n");


    return SYS_ERR_OK;
} 