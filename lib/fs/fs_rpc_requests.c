#include <aos/aos_rpc.h>
#include <fs/fs_rpc.h>
#include <fs/fat32fs.h>
#include <aos/nameserver.h>
#include <fs/fs_rpc_requests.h>
#include <aos/systime.h>


#define SERVICE_GLUE_AND_SEND(chan, type, request, payload, payload_size, response,      \
                              response_bytes)                                            \
    do {                                                                                 \
        char *ns_request;                                                                \
        size_t ns_size = sizeof(fs_msg_type_t) + sizeof(request) + payload_size;         \
        ns_request = malloc(ns_size);                                                    \
        *(fs_msg_type_t *)(ns_request) = (type);                                         \
        memcpy(ns_request + sizeof(fs_msg_type_t), &(request), sizeof(request));         \
        memcpy(ns_request + sizeof(fs_msg_type_t) + sizeof(request), payload,            \
               payload_size);                                                            \
                                                                                         \
        err = nameservice_rpc(chan, ns_request, ns_size, response, response_bytes,       \
                              NULL_CAP, NULL);                                           \
        free(ns_request);                                                                \
    } while (0);

#define SERVICE_SEND(chan, type, request, response, response_bytes)                      \
    do {                                                                                 \
        char ns_request[sizeof(fs_msg_type_t) + sizeof(request)];                        \
        size_t ns_size = sizeof(fs_msg_type_t) + sizeof(request);                        \
        *(fs_msg_type_t *)(ns_request) = (type);                                         \
        memcpy(ns_request + sizeof(fs_msg_type_t), &(request), sizeof(request));         \
        err = nameservice_rpc(chan, ns_request, ns_size, response, response_bytes,       \
                              NULL_CAP, NULL);                                           \
    } while (0);


errval_t aos_rpc_fs_open(nameservice_chan_t chan, const char *path, int flags,
                         struct fat32fs_handle **rethandle)
{
    errval_t err;
    struct rpc_fs_open_request open_request = {
        .pid = disp_get_domain_id(),
        .flags = flags,
    };

    struct rpc_fs_open_response *response;
    SERVICE_GLUE_AND_SEND(chan, AosRpcFsOpen, open_request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    // TODO need to free response too?
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in fopen via RPC\n");
        return err;
    }

    err = response->err;
    if (err_is_fail(err)) {
        free(response);
        return err;
    }

    if (rethandle) {
        *rethandle = malloc(sizeof(struct fat32fs_handle));
        memcpy(*rethandle, &response->handle, sizeof(struct fat32fs_handle));
    }

    free(response);

    return SYS_ERR_OK;
}


errval_t aos_rpc_fs_create(nameservice_chan_t chan, const char *path, int flags,
                           struct fat32fs_handle **rethandle)
{
    errval_t err;
    struct rpc_fs_create_request create_request = { .flags = flags };
    struct rpc_fs_create_response *response;

    DEBUG_PRINTF("path: %s\n", path);
    SERVICE_GLUE_AND_SEND(chan, AosRpcFsCreate, create_request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    // TODO need to free response too?
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in fopen via RPC\n");
        return err;
    }

    err = response->err;
    if (err_is_fail(err)) {
        free(response);
        return err;
    }

    if (rethandle) {
        *rethandle = malloc(sizeof(struct fat32fs_handle));
        memcpy(*rethandle, &response->handle, sizeof(struct fat32fs_handle));
    }

    free(response);
    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_close(nameservice_chan_t chan, fileref_id_t fid)
{
    errval_t err;
    struct rpc_fs_close_request close_request = { .fid = fid,
                                                  .pid = disp_get_domain_id() };
    struct rpc_fs_err_response *response;

    SERVICE_SEND(chan, AosRpcFsClose, close_request, (void **)&response, NULL);
    // TODO need to free response too?
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in file close via RPC\n");
        return err;
    }

    err = response->err;
    free(response);

    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_read(nameservice_chan_t chan, fileref_id_t fid, void *buf, size_t len,
                         size_t *retlen)
{
    errval_t err;
    size_t bytes_read = 0;
    while (bytes_read != len) {
        size_t read = MIN(len - bytes_read, RPC_FS_RW_CHUNK_SIZE);

        struct rpc_fs_read_request read_request
            = { .pid = disp_get_domain_id(), .fid = fid, .bytes = read };
        struct rpc_fs_read_response *response;

        SERVICE_SEND(chan, AosRpcFsRead, read_request, (void **)&response, NULL);

        if (err_is_fail(err)) {
            DEBUG_PRINTF("error in file read via RPC\n");
            return err;
        }

        err = response->err;
        if (err_is_fail(err)) {
            free(response);
            return err;
        }
        
        memcpy(buf, response->buf, read);
        DEBUG_PRINTF("read %zu bytes of total: %d\n", response->bytes, len);
        bytes_read += response->bytes;
        buf += response->bytes;

        if (response->bytes < read) {
            // EOF reached
            free(response);
            break;
        }
        free(response);
    }

    *retlen = bytes_read;

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_write(nameservice_chan_t chan, fileref_id_t fid, void *src_buf,
                          size_t len, size_t *ret_written)
{
    errval_t err;
    size_t bytes_written = 0;
    char *buf = (char *)src_buf;
    while (bytes_written != len) {
        size_t write = MIN((len - bytes_written), RPC_FS_RW_CHUNK_SIZE);

        struct rpc_fs_write_request write_request = {
            .pid = disp_get_domain_id(),
            .fid = fid,
            .bytes = write,
        };
        struct rpc_fs_write_response *response;

        SERVICE_GLUE_AND_SEND(fs_chan, AosRpcFsWrite, write_request, buf, write,
                              (void **)&response, NULL);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("error in file write via RPC\n");
            return err;
        }

        err = response->err;
        if (err_is_fail(err)) {
            free(response);
            return err;
        }

        bytes_written += response->bytes;
        buf += response->bytes;

        free(response);
    }

    if (ret_written) {
        *ret_written = bytes_written;
    }


    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_lseek(nameservice_chan_t chan, fileref_id_t fid, uint64_t offset,
                          int whence, uint64_t *retpos)
{
    errval_t err;

    struct rpc_fs_lseek_request lseek_request = {
        .fid = fid,
        .offset = offset,
        .whence = whence,
    };

    struct rpc_fs_lseek_response *response;
    SERVICE_SEND(chan, AosRpcFsLSeek, lseek_request, (void **)&response, NULL);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in file lseek via RPC\n");
        return err;
    }
    err = response->err;
    if (err_is_fail(err)) {
        free(response);
        return err;
    }

    if (retpos) {
        *retpos = response->new_offset;
    }

    free(response);

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_dir_action(nameservice_chan_t chan, const char *path, bool is_mk)
{
    errval_t err;

    struct rpc_fs_path_request mkdir_request = {};

    fs_msg_type_t action = (is_mk) ? AosRpcFsMkDir : AosRpcFsRmDir;

    struct rpc_fs_err_response *response;
    SERVICE_GLUE_AND_SEND(chan, action, mkdir_request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in file mkdir via RPC\n");
        return err;
    }

    err = response->err;
    free(response);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_rm(nameservice_chan_t chan, const char *path)
{
    errval_t err;
    struct rpc_fs_path_request rm_request = {};
    struct rpc_fs_err_response *response;
    SERVICE_GLUE_AND_SEND(chan, AosRpcFsRm, rm_request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    err = response->err;
    free(response);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_opendir(nameservice_chan_t chan, const char *path,
                            struct fat32fs_handle **rethandle)
{
    errval_t err;
    struct rpc_fs_path_request request = {};
    struct rpc_fs_opendir_response *response;
    SERVICE_GLUE_AND_SEND(chan, AosRpcFsOpenDir, request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in file open dir via RPC\n");
        return err;
    }

    err = response->err;
    if (err_is_fail(err)) {
        free(response);
        return err;
    }

    DEBUG_PRINTF("got a handle with fid %d\n", response->handle.fid);
    *rethandle = malloc(sizeof(struct fat32fs_handle));
    **rethandle = response->handle;
    free(response);
    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_readdir(nameservice_chan_t chan, fileref_id_t fid,
                            struct fs_fileinfo *retfinfo, char **retname)
{
    errval_t err;
    struct rpc_fs_readdir_request readdir_request = {
        .fid = fid,
    };
    struct rpc_fs_readdir_response *response;
    SERVICE_SEND(chan, AosRpcFsReadDir, readdir_request, (void **)&response, NULL);
    if (err_is_fail(err)) {
        return err;
    }
    err = response->err;
    if (err_is_fail(err)) {
        free(response);
        return err;
    }
    if (retfinfo) {
        *retfinfo = response->info;
    }

    if (retname) {
        *retname = strdup(response->name);
    }

    free(response);
    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_fstat(nameservice_chan_t chan, fileref_id_t fid,
                          struct fs_fileinfo *retstat)
{
    errval_t err;

    struct rpc_fs_fstat_request fstat_request = {
        .fid = fid,
    };

    struct rpc_fs_fstat_response *response;
    SERVICE_SEND(chan, AosRpcFsFStat, fstat_request, (void **)&response, NULL);

    err = response->err;
    if (err_is_fail(err)) {
        free(response);
        return err;
    }
    *retstat = response->info;

    free(response);
    return SYS_ERR_OK;
}
