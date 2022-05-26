#include <aos/aos_rpc.h>
#include <fs/fs_rpc.h>
#include <fs/fat32fs.h>

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

errval_t aos_rpc_fs_open(struct aos_rpc *aos_rpc, char *path, int flags, struct fat32fs_handle **rethandle)
{
    errval_t err;

    struct rpc_fs_open_request open_request = {
        .pid = disp_get_domain_id(),
        .flags = flags,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(aos_rpc, AosRpcFsOpen, &open_request, sizeof(open_request), true, path,
                strlen(path) + 1, &response);

    struct rpc_fs_open_response *open_response
        = (struct rpc_fs_open_response *)response.payload;

    err = open_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to open file");
        return err_push(err, FS_ERR_OPEN);
    }

    if(rethandle){
        *rethandle = malloc(sizeof(struct fat32fs_handle));
        memcpy(*rethandle, &open_response->handle, sizeof(struct fat32fs_handle));
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_close(struct aos_rpc *aos_rpc, fileref_id_t fid){
    errval_t err;

    struct rpc_fs_close_request close_request = {
        .pid = disp_get_domain_id(),
        .fid = fid,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(aos_rpc, AosRpcFsClose, &close_request, sizeof(close_request), false, NULL, 0, &response);

    struct rpc_fs_err_response *close_response
        = (struct rpc_fs_err_response *)response.payload;

    err = close_response->err;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to close file");
        return err_push(err, FS_ERR_CLOSE);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_fs_read(struct aos_rpc *aos_rpc, fileref_id_t fid, void *buf, size_t len){
    size_t bytes_read = 0;
    while(bytes_read){
        size_t read = MIN(len, RPC_FS_RW_CHUNK_SIZE);

        struct rpc_fs_read_request read_request = {
            .pid = disp_get_domain_id(),
            .fid = fid,
        };

        struct aos_rpc_msg response;
        rpc_fs_call(aos_rpc, AosRpcFsRead, &read_request, sizeof(read_request), false, NULL, 0, &response);

        struct rpc_fs_read_response *read_response
            = (struct rpc_fs_read_response *)response.payload;
        
        errval_t err = read_response->err;
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to read file");
            return err_push(err, FS_ERR_READ);
        }

        memcpy(buf, read_response->buf, read);
        bytes_read += read;
        buf += read;
    }
}

errval_t aos_rpc_fs_write(struct aos_rpc *aos_rpc, fileref_id_t fid, void *buf, size_t len){
    size_t bytes_written = 0;
    while(bytes_written){
        size_t write = MIN(len, RPC_FS_RW_CHUNK_SIZE);

        struct rpc_fs_write_request write_request = {
            .pid = disp_get_domain_id(),
            .fid = fid,
            .bytes = write,
        };

        struct aos_rpc_msg response;
        rpc_fs_call(aos_rpc, AosRpcFsWrite, &write_request, sizeof(write_request), true, buf, write, &response);

        struct rpc_fs_err_response *write_response
            = (struct rpc_fs_err_response *)response.payload;

        errval_t err = write_response->err;
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write file");
            return err_push(err, FS_ERR_WRITE);
        }

        bytes_written += write;
        buf += write;
    }
}

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

errval_t aos_rpc_fs_lseek(struct aos_rpc *aos_rpc, fileref_id_t fid, uint64_t offset, int whence, uint64_t *retpos){
    errval_t err;

    struct rpc_fs_lseek_request lseek_request = {
        .fid = fid,
        .offset = offset,
        .whence = whence,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(aos_rpc, AosRpcFsLSeek, &lseek_request, sizeof(lseek_request), false, NULL, 0, &response);

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


errval_t aos_rpc_fs_fstat(struct aos_rpc *rpc, fileref_id_t fid, struct fs_fileinfo *retstat){
    errval_t err;

    struct rpc_fs_fstat_request fstat_request = {
        .fid = fid,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(rpc, AosRpcFsFStat, &fstat_request, sizeof(fstat_request), false, NULL, 0, &response);

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

errval_t aos_rpc_readdir(struct aos_rpc *rpc, fileref_id_t fid, struct fs_fileinfo *retfinfo, char **retname){
    errval_t err;

    struct rpc_fs_readdir_request readdir_request = {
        .fid = fid,
    };

    struct aos_rpc_msg response;
    rpc_fs_call(rpc, AosRpcFsReadDir, &readdir_request, sizeof(readdir_request), false, NULL, 0, &response);

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