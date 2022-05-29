#ifndef _LIB_BARRELFISH_AOS_L_MESSAGES_TYPES_H
#define _LIB_BARRELFISH_AOS_L_MESSAGES_TYPES_H

#include <aos/aos.h>

typedef enum aos_rpc_msg_type {
    AosRpcHandshake = 1,
    AosRpcSendNumber,
    AosRpcSendNumberResponse,
    AosRpcSendString,
    AosRpcSendStringResponse,
    AosRpcRamCapRequest,
    AosRpcRamCapResponse,
    AosRpcSpawnRequest,
    AosRpcSpawnResponse,
    AosRpcKillRequest,
    AosRpcKillResponse,
    AosRpcSerialWriteChar,
    AosRpcSerialReadChar,
    AosRpcSerialReadCharResponse,
    AosRpcSerialWriteCharResponse,
    AosRpcPid2Name,
    AosRpcPid2NameResponse,
    AosRpcGetAllPids,
    AosRpcGetAllPidsResponse,
    AosRpcUmpBindRequest,
    AosRpcUmpBindResponse,
    AosRpcPing,
    AosRpcPong,
    AosRpcClose,
    AosRpcCloseReponse,
    AosRpcCpuOff,
    AosRpcBind,
    AosRpcBindReponse,
    AosRpcSendBootinfo,
    AosRpcSendMMStrings,
    AosRpcErrvalResponse,
    AosRpcNsRegister,
    AosRpcNsLookup,
    AosRpcNsLookupResponse,
    ///< An LMP bind request consists of a PID corresponding to a domain we would like to
    ///< bind to. The response is an errval response with the cap of the server endpoint.
    AosRpcLmpBind,
    AosRpcClientRequest,
    AosRpcServerResponse
} aos_rpc_msg_type_t;

struct aos_rpc_msg {
    aos_rpc_msg_type_t type;
    char *payload;
    size_t bytes;
    struct capref cap;
};

struct ram_cap_request {
    size_t bytes;
    size_t alignment;
};

#endif