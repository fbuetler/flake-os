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
#include <aos/nameserver.h>
#include <collections/path_list.h>
#include <aos/systime.h>

static errval_t skip_mountpoint(char **path)
{
    if (strncmp(fs_mount.path, *path, strlen(fs_mount.path)) == 0) {
        *path += strlen(fs_mount.path);
        return SYS_ERR_OK;
    }
    return FS_ERR_NOTFOUND;
}

static char *process_path(char *old_path)
{
    char *path;
    path = clean_path(old_path);
    if (!path) {
        return NULL;
    }
    char *skipped = path;
    if (err_is_fail(skip_mountpoint(&skipped))) {
        free(path);
        return NULL;
    }
    if (*skipped == 0) {
        skipped = strdup("/");
    } else {
        skipped = strdup(skipped);
    }
    free(path);

    return skipped;
}

#define SET_MSG_RESPONSE(payload, payload_size)                                          \
    do {                                                                                 \
        *msg_response = (void *)(payload);                                               \
        *msg_response_bytes = (payload_size);                                            \
    } while (0)

#define FS_LOCK thread_mutex_lock(&fs_state.mutex);
#define FS_UNLOCK thread_mutex_unlock(&fs_state.mutex);


void fs_srv_handler(void *st, void *message, size_t bytes, void **msg_response,
                    size_t *msg_response_bytes, struct capref tx_cap,
                    struct capref *rx_cap)
{
    DEBUG_PRINTF("server: got a request: %d bytes\n", bytes);
    struct rpc_fs_msg *msg = (struct rpc_fs_msg *)message;
    errval_t err;
    void *request = (void *)msg->msg;

    switch (msg->type) {
    case AosRpcFsOpen: {
        struct rpc_fs_open_request *args = request;
        struct fat32fs_handle *rethandle;
        struct rpc_fs_open_response *response = malloc(
            sizeof(struct rpc_fs_open_response));
        char *path = process_path(args->path);
        if (!path) {
            response->err = FS_ERR_NOTFOUND;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_open_response));
            return;
        }

        FS_LOCK;
        err = fat32fs_open(args->pid, NULL, path, args->flags, &rethandle);
        FS_UNLOCK;
        response->err = err;
        if (err_is_ok(err)) {
            response->handle = *rethandle;
        }
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_open_response));
        free(path);
        return;
    }
    case AosRpcFsCreate: {
        struct rpc_fs_create_request *args = request;
        struct fat32fs_handle *rethandle;
        struct rpc_fs_create_response *response = malloc(
            sizeof(struct rpc_fs_create_response));
        // TODO security for pathlen
        char *path = process_path(args->path);
        if (!path) {
            response->err = FS_ERR_NOTFOUND;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_create_response));
            return;
        }
        FS_LOCK;
        err = fat32fs_create(0, path, args->flags, &rethandle);
        FS_UNLOCK;
        response->err = err;
        if (err_is_ok(err)) {
            response->handle = *rethandle;
        }
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_create_response));
        free(path);
        return;
    }
    case AosRpcFsClose: {
        struct rpc_fs_close_request *args = request;
        struct rpc_fs_err_response *response = malloc(sizeof(struct rpc_fs_err_response));

        FS_LOCK;
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        if (!handle) {
            FS_UNLOCK;
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
            return;
        }

        fat32fs_handle_close(handle);
        FS_UNLOCK;
        response->err = SYS_ERR_OK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
        return;
    }
    case AosRpcFsWrite: {
        // currently will assume that it fits into 1024 bytes
        struct rpc_fs_write_request *args = request;
        // get the handle
        struct rpc_fs_write_response *response = malloc(
            sizeof(struct rpc_fs_write_response));
        // write the data
        size_t payload_size = MIN(args->bytes, RPC_FS_RW_CHUNK_SIZE);
        FS_LOCK;
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              (uint64_t)args->fid);
        if (!handle) {
            FS_UNLOCK;
            // send error
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_write_response));
            return;
        }

        size_t bytes_written;
        uint32_t old_fsize = handle->dirent->size;
        response->err = fat32fs_write(handle, args->buf, payload_size, &bytes_written);
        if(handle->dirent->size > old_fsize){
            // update any other open handles
            fat32fs_update_all_handles_to(handle->path, handle->dirent->size);
        }

        FS_UNLOCK;
        response->bytes = bytes_written;
        // send back response
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_write_response));
        return;
    }
    case AosRpcFsRead: {
        struct rpc_fs_read_request *args = (struct rpc_fs_read_request *)request;
        struct rpc_fs_read_response *response;
        size_t read = MIN(args->bytes, RPC_FS_RW_CHUNK_SIZE);
        FS_LOCK;
        // get the handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        if (!handle) {
            FS_UNLOCK;
            // send error
            response = malloc(sizeof(struct rpc_fs_read_response));
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_write_response));
            return;
        }
        // read the data
        uint32_t current_offset = handle->u.file_offset;
        size_t bytes_read;
        response = malloc(sizeof(struct rpc_fs_read_response) + read);
        err = fat32fs_read(handle, (void *)(response + 1), read, &bytes_read);
        FS_UNLOCK;
        if (err_is_fail(err)) {
            // send error
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_write_response));
            return;
        }
        response->bytes = bytes_read;
        response->offset = current_offset;
        response->err = SYS_ERR_OK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_read_response) + read);
        return;
    }
    case AosRpcFsLSeek: {
        struct rpc_fs_lseek_request *args = (struct rpc_fs_lseek_request *)request;
        struct rpc_fs_lseek_response *response = malloc(
            sizeof(struct rpc_fs_lseek_response));
        
        FS_LOCK;
        // get the handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        if (!handle) {
            FS_UNLOCK;
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_lseek_response));
            return;
        }

        err = fat32fs_seek(handle, args->whence, args->offset);
        if (err_is_fail(err)) {
            FS_UNLOCK;
            response->err = err;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_lseek_response));
            return;
        }

        err = fat32fs_tell(handle, &response->new_offset);
        FS_UNLOCK;
        if (err_is_fail(err)) {
            response->err = err;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_lseek_response));
            return;
        }

        response->err = SYS_ERR_OK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_lseek_response));
        return;
    }
    case AosRpcFsMkDir: {
        struct rpc_fs_path_request *args = (struct rpc_fs_path_request *)request;
        // check if string is terminated
        struct rpc_fs_err_response *response = malloc(sizeof(struct rpc_fs_err_response));
        char *path = process_path(args->path);
        if (!path) {
            response->err = FS_ERR_NOTFOUND;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
            return;
        }
        FS_LOCK;
        response->err = fat32fs_mkdir(path);
        FS_UNLOCK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
        free(path);
        return;
    }
    case AosRpcFsRmDir: {
        struct rpc_fs_path_request *args = (struct rpc_fs_path_request *)request;
        // check if string is terminated
        struct rpc_fs_err_response *response = malloc(sizeof(struct rpc_fs_err_response));
        char *path = process_path(args->path);
        if (!path) {
            response->err = FS_ERR_NOTFOUND;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
            return;
        }
        FS_LOCK;
        // check if dir is opened anywhere. If so, return error
        if(hashmap_get(&fs_state.path2handle, path, strlen(path))){
            FS_UNLOCK;
            response->err = FS_ERR_IS_OPEN;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
            free(path);
            return;
        }
        response->err = fat32fs_rmdir(path);
        FS_UNLOCK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
        free(path);
        return;
    }
    case AosRpcFsRm: {
        struct rpc_fs_path_request *args = (struct rpc_fs_path_request *)request;
        // check if string is terminated
        struct rpc_fs_err_response *response = malloc(sizeof(struct rpc_fs_err_response));
        char *path = process_path(args->path);
        if (!path) {
            response->err = FS_ERR_NOTFOUND;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
            return;
        }
        FS_LOCK;
        // check if dir is opened anywhere. If so, return error
        if(hashmap_get(&fs_state.path2handle, path, strlen(path))){
            FS_UNLOCK;
            response->err = FS_ERR_IS_OPEN;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
            free(path);
            return;
        }
        response->err = fat32fs_rm(path);
        FS_UNLOCK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_err_response));
        free(path);
        return;
    }
    case AosRpcFsOpenDir: {
        struct rpc_fs_path_request *args = (struct rpc_fs_path_request *)request;
        // check if string is terminated
        struct rpc_fs_opendir_response *response = malloc(
            sizeof(struct rpc_fs_opendir_response));
        struct fat32fs_handle *handle;
        char *path = process_path(args->path);
        if (!path) {
            response->err = FS_ERR_NOTFOUND;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_opendir_response));
            return;
        }
        FS_LOCK;
        response->err = fat32fs_opendir(0, path, &handle);
        FS_UNLOCK;
        if(handle){
            response->handle = *handle;
        }
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_opendir_response));
        free(path);
        return;
    }
    case AosRpcFsReadDir: {
        struct rpc_fs_readdir_request *args = (struct rpc_fs_readdir_request *)request;
        struct rpc_fs_readdir_response *response;

        FS_LOCK;
        // get handle
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        if (!handle) {
            FS_UNLOCK;
            // send error
            response = malloc(sizeof(struct rpc_fs_readdir_response));
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_readdir_response));
            return;
        }
        char *retname;
        struct fs_fileinfo info;
        err = fat32fs_dir_read_next(handle, &retname, &info);
        FS_UNLOCK;
        if(err_is_fail(err)){
            response = malloc(sizeof(struct rpc_fs_readdir_response));
            response->err = err;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_readdir_response));
            return;
        }
        // glue the DYNAMICALLY sized retname to the response
        size_t payload_size = sizeof(struct rpc_fs_readdir_response) + strlen(retname) + 1;
        response = malloc(payload_size);
        memcpy(response + 1, retname,
               payload_size - sizeof(struct rpc_fs_readdir_response));
        free(retname);
        response->err = err;
        response->info = info;

        SET_MSG_RESPONSE(response, payload_size);
        return;
    }

    case AosRpcFsFStat: {
        struct rpc_fs_fstat_request *args = (struct rpc_fs_fstat_request *)request;
        struct rpc_fs_fstat_response *response = malloc(sizeof(struct rpc_fs_fstat_response));

        FS_LOCK;
        struct fat32fs_handle *handle = collections_hash_find(fs_state.fid2handle,
                                                              args->fid);
        if (!handle) {
            FS_UNLOCK;
            response->err = FS_ERR_INVALID_FH;
            SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_fstat_response));
            return;
        }
        response->err = fat32fs_fstat(handle, &response->info);
        FS_UNLOCK;
        SET_MSG_RESPONSE(response, sizeof(struct rpc_fs_fstat_response));
        return;
    }

    default: {
        DEBUG_PRINTF("unknown message type received in FS\n");
    }
    }
}


errval_t fs_handle_rpc_req(struct aos_lmp *lmp)
{

    return SYS_ERR_OK;
}