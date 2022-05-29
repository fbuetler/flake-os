#ifndef __FS_RPC_REQUESTS_H
#define __FS_RPC_REQUESTS_H

#include <aos/aos.h>
#include <aos/nameserver.h>
#include <fs/fs.h>
#include <fs/fat32fs.h>

errval_t aos_rpc_fs_open(nameservice_chan_t chan, const char *path, int flags,
                         struct fat32fs_handle **rethandle);

errval_t aos_rpc_fs_create(nameservice_chan_t chan, const char *path, int flags,
                           struct fat32fs_handle **rethandle);

errval_t aos_rpc_fs_close(nameservice_chan_t chan, fileref_id_t fid);

errval_t aos_rpc_fs_read(nameservice_chan_t chan, fileref_id_t fid, void *buf, size_t len,
                         size_t *bytes_read);

errval_t aos_rpc_fs_write(nameservice_chan_t chan, fileref_id_t fid, void *buf,
                          size_t len, size_t *ret_written);

errval_t aos_rpc_fs_lseek(nameservice_chan_t chan, fileref_id_t fid, uint64_t offset,
                          int whence, uint64_t *retpos);

errval_t aos_rpc_fs_dir_action(nameservice_chan_t chan, const char *path, bool is_mk);

errval_t aos_rpc_fs_rm(nameservice_chan_t chan, const char *path);

errval_t aos_rpc_fs_opendir(nameservice_chan_t chan, const char *path,
                            struct fat32fs_handle **rethandle);

errval_t aos_rpc_fs_readdir(nameservice_chan_t chan, fileref_id_t fid,
                            struct fs_fileinfo *retfinfo, char **retname);
    
errval_t aos_rpc_fs_fstat(nameservice_chan_t chan, fileref_id_t fid,
                          struct fs_fileinfo *retstat);

#endif