#ifndef __fs_FS_H__
#define __fs_FS_H__

#include <fs/fat32.h>
#include <fs/fs.h>
#include <fs/dirent.h>
#include <collections/str_hashmap.h>
#include <aos/nameserver.h>
#include <fs/fat32fs.h>

#define RPC_FS_RW_CHUNK_SIZE 1024

struct fat32fs_dirent {
    char *name;
    size_t size;
    bool is_dir;
    uint32_t dir_cluster;
    uint32_t dir_index;
    uint32_t start_data_cluster;
};

struct fat32fs_handle {
    int flags;
    fileref_id_t fid;
    domainid_t pid;

    char *path;
    struct fat32fs_dirent *dirent;

    union {
        uint32_t dir_offset;
        uint32_t file_offset;
    } u;

    uint32_t curr_data_cluster;
};

struct fat32fs_mount {
    char *path;
};

struct handle_list_node{
    struct fat32fs_handle *handle;
    struct handle_list_node *next;
};

struct fs_state {
    struct fat32 fat32;
    fileref_id_t curr_fid_counter;
    collections_hash_table *fid2handle;
    struct hashmap_s path2handle;
    struct thread_mutex mutex;
};

struct fs_state fs_state;

nameservice_chan_t fs_chan;
struct fat32fs_mount fs_mount;

void fat32fs_add_file_handler(domainid_t pid, struct fat32fs_handle *handle);

struct fat32fs_handle *handle_open(domainid_t pid, struct fat32fs_dirent *d, const char *path);

errval_t fat32fs_read(struct fat32fs_handle *h, void *buffer, size_t bytes,
                      size_t *bytes_read);

errval_t fat32fs_write(struct fat32fs_handle *h, const void *buf, size_t bytes,
                       size_t *bytes_written);

errval_t fat32fs_open(domainid_t pid, struct fat32fs_mount *mount, const char *path,
                      int flags, struct fat32fs_handle **rethandle);

errval_t fat32fs_seek(struct fat32fs_handle *h, enum fs_seekpos whence, off_t offset);

errval_t fat32fs_tell(struct fat32fs_handle *h, uint32_t *pos);

errval_t fat32fs_create(domainid_t pid, char *path, int flags,
                        struct fat32fs_handle **rethandle);

void fat32fs_handle_close(struct fat32fs_handle *h);

errval_t fat32fs_mkdir(const char *path);

errval_t fat32fs_rm(const char *path);

errval_t fat32fs_fstat(struct fat32fs_handle *h, struct fs_fileinfo *b);

errval_t fat32fs_rmdir(const char *path);

errval_t fat32fs_opendir(domainid_t pid, const char *full_path,
                         struct fat32fs_handle **rethandle);

errval_t fat32fs_dir_read_next(struct fat32fs_handle *h, char **retname,
                               struct fs_fileinfo *info);

void fs_init(void);

void fat32fs_mount(char *path);

void  fat32fs_update_all_handles_to(const char *path, uint32_t max_offset);

#endif