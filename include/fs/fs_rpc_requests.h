#ifndef __FS_RPC_REQUESTS_H
#define __FS_RPC_REQUESTS_H
errval_t aos_rpc_fs_open(nameservice_chan_t chan, char *path, int flags, struct fat32fs_handle **rethandle);
errval_t aos_rpc_fs_create(nameservice_chan_t chan, char *path, int flags, struct fat32fs_handle **rethandle);
errval_t aos_rpc_fs_close(nameservice_chan_t chan, fileref_id_t fid);


errval_t aos_rpc_fs_read(nameservice_chan_t chan, fileref_id_t fid, void *buf, size_t len, size_t *bytes_read);
errval_t aos_rpc_fs_write(nameservice_chan_t chan, fileref_id_t fid, void *buf, size_t len, size_t *ret_written);
#endif