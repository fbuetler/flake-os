#include <aos/aos_rpc.h>
#include <fs/fs_rpc.h>
#include <fs/fat32fs.h>
#include <aos/nameserver.h>
#include <fs/fs_rpc_requests.h>

/*
static char *glue_header(void *header, void *payload, size_t header_len,
                         size_t payload_len)
{
    char *buf = malloc(header_len + payload_len);
    memcpy(buf, header, header_len);
    memcpy(buf + header_len, payload, payload_len);
    return buf;
}
static errval_t rpc_fs_call(struct aos_rpc *rpc, aos_rpc_msg_type_t type, void *header,
                            size_t header_len, bool glue_payload, void *payload,
                            size_t payload_len, struct aos_rpc_msg *response)
{
    void *marshalled_payload;
    size_t marshalled_payload_size;
    if (glue_payload) {
        marshalled_payload = glue_header(header, payload, header_len, payload_len);
        marshalled_payload = payload_len + header_len;
    } else {
        marshalled_payload = payload;
        marshalled_payload_size = header_len;
    }

    struct aos_rpc_msg request = { .type = type,
                                   .payload = (char *)marshalled_payload,
                                   .bytes = marshalled_payload_size,
                                   .cap = NULL_CAP };

    errval_t err = aos_rpc_call(rpc, request, &response, glue_payload);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to send message");
        return err_push(err, LIB_ERR_RPC_SEND);
    }
}
*/


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
        DEBUG_ERR(err, "failed to open file");
        return err_push(err, FS_ERR_OPEN);
    }

    if (rethandle) {
        *rethandle = malloc(sizeof(struct fat32fs_handle));
        memcpy(*rethandle, &response->handle, sizeof(struct fat32fs_handle));
    }

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
        DEBUG_ERR(err, "failed to create file");
        return err;
    }

    if (rethandle) {
        *rethandle = malloc(sizeof(struct fat32fs_handle));
        memcpy(*rethandle, &response->handle, sizeof(struct fat32fs_handle));
    }

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
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to close file");
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
            DEBUG_ERR(err, "failed to read file");
            return err_push(err, FS_ERR_READ);
        }

        memcpy(buf, response->buf, read);
        debug_printf("read %zu bytes of total: %d\n", response->bytes, len);
        bytes_read += response->bytes;
        buf += response->bytes;

        if (response->bytes < read) {
            // EOF reached
            break;
        }
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
            DEBUG_ERR(err, "failed to write file");
            return err_push(err, FS_ERR_WRITE);
        }

        bytes_written += response->bytes;
        buf += response->bytes;
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
        DEBUG_ERR(err, "failed to lseek file");
        return err_push(err, FS_ERR_LSEEK);
    }

    if (retpos) {
        *retpos = response->new_offset;
    }

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
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to mkdir file");
        return err_push(err, FS_ERR_MKDIR);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_rm(nameservice_chan_t chan, const char *path)
{
    errval_t err;
    struct rpc_fs_path_request rm_request = {};
    struct rpc_fs_err_response *response;
    SERVICE_GLUE_AND_SEND(chan, AosRpcFsMkDir, rm_request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in file mkdir via RPC\n");
        return err;
    }

    err = response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to mkdir file");
        return err_push(err, FS_ERR_MKDIR);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_opendir(nameservice_chan_t chan, const char *path,
                            struct fat32fs_handle **rethandle)
{
    errval_t err;
    struct rpc_fs_path_request request = {};
    struct rpc_fs_opendir_response *response;
    SERVICE_GLUE_AND_SEND(chan, FsOpenDir, request, path, strlen(path) + 1,
                          (void **)&response, NULL);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("error in file open dir via RPC\n");
        return err;
    }

    err = response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to open dir");
        return err_push(err, FS_ERR_MKDIR);
    }

    *rethandle = malloc(sizeof(struct fat32fs_handle));
    **rethandle = response->handle;

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
        DEBUG_PRINTF("error in file readdir via RPC\n");
        return err;
    }
    err = response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to read dir");
        return err_push(err, FS_ERR_READ_DIR);
    }
    if (retfinfo) {
        *retfinfo = response->info;
    }
    if (retname) {
        *retname = strdup(response->name);
    }
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
        DEBUG_ERR(err, "failed to fstat file");
        return err_push(err, FS_ERR_FSTAT);
    }
    *retstat = response->info;

    return SYS_ERR_OK;
}

/*
errval_t aos_rpc_fs_rm(struct aos_rpc *aos_rpc, char *path){
    errval_t err;

    struct rpc_fs_path_request rm_request = {
    };

    struct aos_rpc_msg response;
    rpc_fs_call(aos_rpc, AosRpcFsRm, &rm_request, sizeof(rm_request), true, path,
                strlen(path) + 1, &response);

    struct rpc_fs_err_response *rm_response
        = (struct rpc_fs_err_response *)response.payload;

    err = rm_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to remove file");
        return err_push(err, FS_ERR_RM);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_lseek(struct aos_rpc *aos_rpc, fileref_id_t fid, uint64_t offset, int
whence, uint64_t *retpos){ errval_t err;

    struct rpc_fs_lseek_request lseek_request = {
        .fid = fid,
        .offset = offset,
        .whence = whence,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(aos_rpc, AosRpcFsLSeek, &lseek_request, sizeof(lseek_request), false,
NULL, 0, &response);

    struct rpc_fs_lseek_response *lseek_response
        = (struct rpc_fs_lseek_response *)response.payload;

    err = lseek_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to lseek file");
        return err_push(err, FS_ERR_LSEEK);
    }

    if(retpos){
        *retpos = lseek_response->new_offset;
    }

    return SYS_ERR_OK;
}


errval_t aos_rpc_fs_fstat(struct aos_rpc *rpc, fileref_id_t fid, struct fs_fileinfo
*retstat){ errval_t err;

    struct rpc_fs_fstat_request fstat_request = {
        .fid = fid,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(rpc, AosRpcFsFStat, &fstat_request, sizeof(fstat_request), false, NULL, 0,
&response);

    struct rpc_fs_fstat_response *fstat_response
        = (struct rpc_fs_fstat_response *)response.payload;

    err = fstat_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to fstat file");
        return err_push(err, FS_ERR_FSTAT);
    }
    *retstat = fstat_response->info;

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_mkdir(struct aos_rpc *rpc, char *path){
    errval_t err;

    struct rpc_fs_path_request mkdir_request = {
    };

    struct aos_rpc_msg response;
    rpc_fs_call(rpc, AosRpcFsMkdir, &mkdir_request, sizeof(mkdir_request), true, path,
                strlen(path) + 1, &response);

    struct rpc_fs_err_response *mkdir_response
        = (struct rpc_fs_err_response *)response.payload;

    err = mkdir_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to mkdir file");
        return err_push(err, FS_ERR_MKDIR);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_rmdir(struct aos_rpc *rpc, char *path){
    errval_t err;

    struct rpc_fs_path_request rmdir_request = {
    };

    struct aos_rpc_msg response;
    rpc_fs_call(rpc, AosRpcFsRmdir, &rmdir_request, sizeof(rmdir_request), true, path,
                strlen(path) + 1, &response);

    struct rpc_fs_err_response *rmdir_response
        = (struct rpc_fs_err_response *)response.payload;

    err = rmdir_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to rmdir file");
        return err_push(err, FS_ERR_RMDIR);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_readdir(struct aos_rpc *rpc, fileref_id_t fid, struct fs_fileinfo
*retfinfo, char **retname){ errval_t err;

    struct rpc_fs_readdir_request readdir_request = {
        .fid = fid,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(rpc, AosRpcFsReadDir, &readdir_request, sizeof(readdir_request), false,
NULL, 0, &response);

    struct rpc_fs_readdir_response *read_dir_response
        = (struct rpc_fs_readdir_response *)response.payload;

    err = read_dir_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to read dir");
        return err_push(err, FS_ERR_READ_DIR);
    }
    *retfinfo = read_dir_response->info;
    *retname = strdup(read_dir_response->name);

    return SYS_ERR_OK;
}
*/