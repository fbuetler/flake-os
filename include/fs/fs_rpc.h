#ifndef __FS_RPC_H__
#define __FS_RPC_H__

#include <aos/aos.h>
#include <fs/fat32fs.h>

struct rpc_fs_open_request{
    domainid_t pid;
    int flags;
    char path[0];
};
struct rpc_fs_open_response{
    errval_t err;
    struct fat32fs_handle handle;
};

struct rpc_fs_close_request{
    domainid_t pid;
    domainid_t fid;
};

struct rpc_fs_read_request{
    domainid_t pid;
    fileref_id_t fid;
    uint32_t bytes;
};

struct rpc_fs_read_response{
    errval_t err;
    uint32_t offset;
    uint32_t bytes;
    char buf[0];
};

struct rpc_fs_path_request{
    char path[0];
};

struct rpc_fs_write_request{
    domainid_t pid;
    domainid_t fid;
    size_t bytes;
    char buf[0];
};

struct rpc_fs_write_response{
    errval_t err;
    size_t bytes;
};

struct rpc_fs_lseek_request{
    fileref_id_t fid;
    off_t offset;
    int whence;
};

struct rpc_fs_lseek_response{
    errval_t err;
    uint32_t new_offset;
};

struct rpc_fs_err_response{
    errval_t err;
};


struct rpc_fs_fstat_request{
    fileref_id_t fid;
};

struct rpc_fs_fstat_response{
    errval_t err;
    struct fs_fileinfo info;
};

struct rpc_fs_mkdir_request{
    char path[0];
};

struct rpc_fs_rmdir_request{
    char path[0];
};

struct rpc_fs_readdir_request{
    fileref_id_t fid;
};

struct rpc_fs_readdir_response{
    errval_t err;
    struct fs_fileinfo info;
    char name[0];
};

errval_t fs_handle_rpc_req(struct aos_lmp *lmp);

#endif