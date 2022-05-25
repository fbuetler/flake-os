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
    AosRpcFsOpen,
    AosRpcFsOpenResponse,
    AosRpcFsClose,
    AosRpcFsCloseResponse,
    AosRpcFsRead,
    AosRpcFsReadResponse,
    AosRpcFsWrite,
    AosRpcFsWriteResponse,
    AosRpcFsRm,
    AosRpcFsRmResponse,
    AosRpcFsLSeek,
    AosRpcFsLSeekResponse,
    AosRpcFsFStat,
    AosRpcFsFStatResponse,
    AosRpcMkDir,
    AosRpcMkDirResponse,
    AosRpcRmDir,
    AosRpcRmDirResponse,
    AosRpcReadDir,
    AosRpcReadDirResponse
} aos_rpc_msg_type_t;

struct aos_rpc_msg {
    aos_rpc_msg_type_t type;
    char *payload;
    size_t bytes;
    struct capref cap;
};

#endif