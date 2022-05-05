#include <aos/rpc.h>

void rpc_init_from_ump(struct rpc *rpc, struct ump_chan *chan){
    rpc->u.ump = *chan;
    rpc->is_lmp = false;
}

void rpc_init_from_lmp(struct rpc *rpc, struct aos_lmp *chan){
    rpc->u.lmp = *chan;
    rpc->is_lmp = true;
}

// TODO-refactor: currently only for static bufs if lmp (no too large messages)
errval_t rpc_call(struct rpc *rpc, struct rpc_msg msg, struct rpc_msg *retmsg){
    errval_t err = SYS_ERR_OK;

    // TODO-refactor: dynamic sizes
    char buf[BASE_PAGE_SIZE];
    if(rpc->is_lmp){
        struct aos_rpc_msg *lmp_msg;
        err = aos_rpc_create_msg_no_pagefault(&lmp_msg, msg.type, msg.bytes, msg.payload, msg.cap, (struct aos_rpc_msg *)buf);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "failed to create message");
            return err;
        }
        err = aos_rpc_call(&rpc->u.lmp, lmp_msg, false);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "failed to send lmp message");
            return err;
        }

        retmsg->payload = rpc->u.lmp.recv_msg->payload;
        retmsg->bytes = rpc->u.lmp.recv_msg->payload_bytes;
        retmsg->type = rpc->u.lmp.recv_msg->message_type;
        retmsg->cap = rpc->u.lmp.recv_msg->cap;

        if(!capcmp(retmsg->cap, NULL_CAP)){
            err = lmp_chan_alloc_recv_slot(&rpc->u.lmp.chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to allocated receive slot");
                err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
                return err;
            }  
        }


    } else {
        if(!capcmp(msg.cap, NULL_CAP)) {
            // TODO-refactor 
        }
        return ump_call(&rpc->u.ump, msg.type, msg.payload, msg.bytes, &retmsg->type, &retmsg->payload, &retmsg->bytes);
    }

    return err;
}

errval_t rpc_bind(struct aos_lmp *init_lmp, struct rpc *rpc, coreid_t core,
                  enum aos_rpc_service service){
    rpc->is_lmp = false;
    errval_t err = ump_bind(init_lmp, &rpc->u.ump, core, service);
    return err;
}