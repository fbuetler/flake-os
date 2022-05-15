#ifndef __fs_FS_H__
#define __fs_FS_H__

#include <fs/fat32.h>
#include <fs/fs.h>
#include <fs/dirent.h>
#include "fs_internal.h"

typedef uint32_t fileref_id_t;

struct fat32fs_dirent {
    char *name;
    size_t size;
    bool is_dir;
    uint32_t dir_sector;
    uint32_t dir_index;
    uint32_t start_data_cluster;
};

struct fat32fs_handle {
    fileref_id_t fid;
    domainid_t pid;

    struct fs_handle common;
    char *path;
    struct fat32fs_dirent *dirent;

    union {
        uint32_t dir_offset;
        uint32_t file_offset;
    } u;

    uint32_t curr_data_cluster;
};

struct fat32fs_mount {
    struct fs_dirent *root;
};

struct fs_state {
    struct fat32 fat32;
    fileref_id_t curr_fid_counter;
};


void fat32fs_add_file_handler(domainid_t pid, struct fat32fs_handle *handle);

struct fat32fs_handle *handle_open(domainid_t pid, struct fat32fs_dirent *d);

void fat32fs_handle_close(struct fat32fs_handle *h);

errval_t fat32fs_read(struct fat32fs_handle *h, void *buffer, size_t bytes,
                      size_t *bytes_read);

errval_t fat32fs_write(struct fat32fs_handle *h, const void *buf, size_t bytes,
                       size_t *bytes_written);

errval_t fat32fs_open(domainid_t pid, struct fat32fs_mount *mount, const char *path,
                      struct fat32fs_handle **rethandle);

errval_t fat32fs_seek(struct fat32fs_handle *h, enum fs_seekpos whence,
                      off_t offset);

errval_t fat32fs_tell(struct fat32fs_handle *h, size_t *pos);

errval_t fat32fs_create(domainid_t pid, char *path, struct fat32fs_handle **rethandle);

void fs_init(void);


#endif