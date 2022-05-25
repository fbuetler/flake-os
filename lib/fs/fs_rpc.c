#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/core_state.h>
#include <aos/capabilities.h>
#include <aos/paging.h>
#include <aos/deferred.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/cache.h>
#include <fs/fat32.h>
#include <fs/fs.h>
#include <fs/fat32fs.h>
#include <fs/dirent.h>
#include <fs/fs_rpc.h>


static inline errval_t lmp_send(struct aos_lmp *lmp, aos_rpc_msg_type_t type,
                                char *payload, size_t payload_size, char *msg_buf)
{
    errval_t err;

    struct aos_lmp_msg *reply;
    err = aos_lmp_create_msg_no_pagefault(&reply, type, payload_size, payload, NULL_CAP,
                                          (struct aos_lmp_msg *)msg_buf);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to create message");
        return err;
    } else {
        err = aos_lmp_send_msg((lmp), reply);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("error sending back lmp msg\n");
            return err;
        }
    }
    return SYS_ERR_OK;
}

#define LMP_SEND(lmp, type, payload, bytes)                                              \
    do {                                                                                 \
        char send_buf[AOS_LMP_MSG_SIZE(bytes)];                                          \
        err = lmp_send((lmp), (type), (char *)(payload), (bytes), send_buf);            \
        if (err_is_fail(err)) {                                                          \
            DEBUG_ERR(err, "lmp_send failed");                                           \
            return err;                                                                      \
        }                                                                                \
    } while (0)

#define LMP_GLUE_HEADER_AND_SEND(lmp, type, payload_header, payload, payload_bytes)      \
    do {                                                                                 \
        int total_bytes = (payload_bytes) + sizeof(payload_header);                      \
        char concat_buf[total_bytes];                                                    \
        memcpy(concat_buf, (payload_header), sizeof(payload_header));                    \
        memcpy(concat_buf + sizeof(payload_header), (payload), (payload_bytes));         \
        LMP_SEND((lmp), (type), concat_buf, total_bytes);                                \
    } while (0)

errval_t fs_handle_rpc_req(struct aos_lmp *lmp)
{
    // refill slot allocator
    struct slot_alloc_state *s = get_slot_alloc_state();
    if (single_slot_alloc_freecount(&s->rootca) <= 10) {
        root_slot_allocator_refill(NULL, NULL);
    }
    errval_t err;

    enum aos_rpc_msg_type msg_type = lmp->recv_msg->message_type;
    char *request = lmp->recv_msg->payload;
    switch (msg_type) {
    case AosRpcFsOpen: {
        struct rpc_fs_open_request *args = (struct rpc_fs_open_request *)request;
        struct fat32fs_handle *rethandle;
        struct rpc_fs_open_response response;

        int pathlen = lmp->recv_msg->payload_bytes - sizeof(struct rpc_fs_open_request)
                      - 1;
        if (args->path[pathlen] != '\0') {
            response.err = FS_ERR_INVALID_PATH;
            LMP_SEND(lmp, AosRpcFsOpenResponse, &response, sizeof(response));
            return response.err;
        }

        err = fat32fs_open(args->pid, NULL, args->path, args->flags, &rethandle);

        response.err = err;
        if (err_is_ok(err)) {
            response.handle = *rethandle;
        }
        // send response
        response.handle = *rethandle;
        LMP_SEND(lmp, AosRpcFsOpenResponse, &response, sizeof(response));
    }
    case AosRpcFsClose: {
        struct rpc_fs_close_request *args = (struct rpc_fs_close_request *)request;

        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        if (!handle) {
            // TODO
            struct rpc_fs_err_response response = { .err = FS_ERR_INVALID_FH };
            LMP_SEND(lmp, AosRpcFsCloseResponse, &response, sizeof(response));
            return response.err;
        }

        fat32fs_handle_close(handle);
        // send response
        struct rpc_fs_err_response response = { .err = SYS_ERR_OK };
        // send response
        LMP_SEND(lmp, AosRpcFsCloseResponse, &response, sizeof(response));
    }
    case AosRpcFsRead: {
        struct rpc_fs_read_request *args = (struct rpc_fs_read_request *)request;
        // get the handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        struct rpc_fs_read_response response;
        if (!handle) {
            // send error
            response.err = FS_ERR_INVALID_FH;
            LMP_SEND(lmp, AosRpcFsReadResponse, &response, sizeof(response));
            return response.err;
        }
        // read the data
        char buf[1024];
        while (args->bytes > 0) {
            size_t read = MIN(args->bytes, sizeof(buf));
            uint32_t current_offset = handle->u.file_offset;
            err = fat32fs_read(handle, buf, read, NULL);
            if (err_is_fail(err)) {
                // send error
                response.err = FS_ERR_INVALID_FH;
                LMP_SEND(lmp, AosRpcFsReadResponse, &response, sizeof(response));
                return response.err;
            }
            args->bytes -= read;
            // send back buf
            response.bytes = read;
            response.offset = current_offset;
            response.err = SYS_ERR_OK;
            LMP_GLUE_HEADER_AND_SEND(lmp, AosRpcFsReadResponse, &response, buf, read);
        }
    }
    case AosRpcFsWrite: {
        // currently will assume that it fits into 1024 bytes
        struct rpc_fs_write_request *args = (struct rpc_fs_write_request *)request;
        // get the handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              (uint64_t)args->fid);
        struct rpc_fs_write_response response;
        if (!handle) {
            // send error
            response.err = FS_ERR_INVALID_FH;
            LMP_SEND(lmp, AosRpcFsWriteResponse, &response, sizeof(response));
            return response.err;
        }
        // write the data
        assert(args->bytes <= 1024);

        size_t bytes_written;
        response.err = fat32fs_write(handle, args->buf, args->bytes, &bytes_written);
        response.bytes = bytes_written;
        // send back response
        LMP_SEND(lmp, AosRpcFsWriteResponse, &response, sizeof(response));
    }
    case AosRpcFsRm: {
        struct rpc_fs_path_request *rm_req = (struct rpc_fs_path_request *)request;
        struct rpc_fs_err_response response;
        int pathlen = lmp->recv_msg->payload_bytes - sizeof(struct rpc_fs_path_request)
                      - 1;
        if (rm_req->path[pathlen] != '\0') {
            response.err = FS_ERR_INVALID_PATH;
            LMP_SEND(lmp, AosRpcFsRmResponse, &response, sizeof(response));
            return response.err;
        }

        // before deleting, we check if the file is open
        // in that case, removing is not allowed!
        if (hashmap_get(&fs_state.path2handle, rm_req->path, pathlen)) {
            response.err = FS_ERR_FILE_OPEN;
            LMP_SEND(lmp, AosRpcFsRmResponse, &response, sizeof(response));
            return response.err;
        }

        // send back repsonse
        response.err = fat32fs_rm(rm_req->path);
        LMP_SEND(lmp, AosRpcFsRmResponse, &response, sizeof(response));
    }
    case AosRpcFsLSeek: {
        struct rpc_fs_lseek_request *args = (struct rpc_fs_lseek_request *)request;
        // get the handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        struct rpc_fs_lseek_response response;
        if (!handle) {
            // send error
            response.err = FS_ERR_INVALID_FH;
            LMP_SEND(lmp, AosRpcFsLSeekResponse, &response, sizeof(response));
            return response.err;
        }

        err = fat32fs_seek(handle, args->whence, args->offset);
        uint32_t new_offset = handle->u.file_offset;
        response.err = err;
        response.new_offset = new_offset;
        LMP_SEND(lmp, AosRpcFsLSeekResponse, &response, sizeof(response));
    }
    case AosRpcFsFStat: {
        struct rpc_fs_fstat_request *args = (struct rpc_fs_fstat_request *)request;

        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        struct rpc_fs_fstat_response response;
        if (!handle) {
            // send error
            response.err = FS_ERR_INVALID_FH;
            LMP_SEND(lmp, AosRpcFsFStatResponse, &response, sizeof(response));
            return response.err;
        }

        struct fs_fileinfo stat;
        err = fat32fs_fstat(handle, &stat);
        response.err = err;
        response.info = stat;
        LMP_SEND(lmp, AosRpcFsFStatResponse, &response, sizeof(response));
    }
    case AosRpcMkDir: {
        struct rpc_fs_path_request *args = (struct rpc_fs_path_request *)request;
        // check if string is terminated
        struct rpc_fs_err_response response;
        if (args->path[sizeof(struct rpc_fs_path_request) + lmp->recv_msg->payload_bytes - 1]
            != '\0') {
            response.err = FS_ERR_INVALID_PATH;
            LMP_SEND(lmp, AosRpcMkDirResponse, &response, sizeof(response));
            return response.err;
        }

        response.err = fat32fs_mkdir(args->path);
        LMP_SEND(lmp, AosRpcMkDirResponse, &response, sizeof(response));
    }
    case AosRpcRmDir: {
        struct rpc_fs_path_request *rm_req = (struct rpc_fs_path_request *)request;
        struct rpc_fs_err_response response = { .err = fat32fs_rmdir(rm_req->path) };
        LMP_SEND(lmp, AosRpcRmDirResponse, &response, sizeof(response));
    }
    case AosRpcReadDir: {
        struct rpc_fs_readdir_request *args = (struct rpc_fs_readdir_request *)request;

        // get handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        struct rpc_fs_readdir_response response;
        if (!handle) {
            // send error
            response.err = FS_ERR_INVALID_FH;
            LMP_SEND(lmp, AosRpcReadDirResponse, &response, sizeof(response));
            return response.err;
        }

        // readdir
        char *retname;
        struct fs_fileinfo info;
        err = fat32fs_dir_read_next(handle, &retname, &info);
        response.err = err;
        response.info = info;
        // glue the DYNAMICALLY sized retname to the response
        size_t payload_size = sizeof(response) + strlen(retname) + 1;
        char *payload = malloc(payload_size);
        memcpy(payload, &response, sizeof(response));
        memcpy(payload + sizeof(response), retname, payload_size - sizeof(response));
        free(retname);

        struct aos_lmp_msg *msg;
        err = aos_lmp_create_msg(&msg, AosRpcReadDirResponse, payload_size, payload,
                                 NULL_CAP);
        free(payload);

        if (err_is_fail(err)) {
            response.err = err;
            LMP_SEND(lmp, AosRpcReadDirResponse, &response, sizeof(response));
            return response.err;
        }

        err = aos_lmp_send_msg(lmp, msg);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't send back readdir response!\n");
        }
        free(msg);
    }
    default: {
        DEBUG_PRINTF("Unknown RPC request %d\n", msg_type);
    }
    }

    return SYS_ERR_OK;
}