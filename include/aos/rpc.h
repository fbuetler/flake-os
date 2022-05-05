#ifndef _INIT_RPC_TMP_H_
#define _INIT_RPC_TMP_H_

#include <aos/aos_rpc.h>
#include <aos/ump_chan.h>

struct rpc{
    union {
        struct aos_lmp lmp;
        struct ump_chan ump;
    } u;
    bool is_lmp;
};

struct rpc_msg{
    aos_rpc_msg_type_t type;
    char *payload;
    size_t bytes;
    struct capref cap;
};

void rpc_init_from_ump(struct rpc *rpc, struct ump_chan *chan);
void rpc_init_from_lmp(struct rpc *rpc, struct aos_lmp *chan);

errval_t rpc_call(struct rpc *rpc, struct rpc_msg msg, struct rpc_msg *retmsg);

errval_t rpc_bind(struct aos_lmp *init_lmp, struct rpc *rpc, coreid_t core,
                  enum aos_rpc_service service);

#endif