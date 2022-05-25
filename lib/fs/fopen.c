/**
 * \file fopen.c
 * \brief
 */


/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <aos/aos.h>

#include <fs/fs.h>
#include <fs/dirent.h>
#include <fs/ramfs.h>
#include <fs/fat32fs.h>
#include "fs_internal.h"
#include <collections/path_list.h>


static void *mount;

/*
 * FD table
 */

#define STDIN_FILENO 0  /* standard input file descriptor */
#define STDOUT_FILENO 1 /* standard output file descriptor */
#define STDERR_FILENO 2 /* standard error file descriptor */

static struct fdtab_entry fdtab[MAX_FD] = {
    [STDIN_FILENO] = {
        .type = FDTAB_TYPE_STDIN,
        .handle = NULL,
    },
    [STDOUT_FILENO] = {
        .type = FDTAB_TYPE_STDOUT,
        .handle = NULL,
    },
    [STDERR_FILENO] = {
        .type = FDTAB_TYPE_STDERR,
        .handle = NULL,
    },
};

static int fdtab_alloc(struct fdtab_entry *h)
{
    for (int fd = MIN_FD; fd < MAX_FD; fd++) {
        if (fdtab[fd].type == FDTAB_TYPE_AVAILABLE) {
            fdtab[fd].inherited = 0;  // Just precautionary
            memcpy(&fdtab[fd], h, sizeof(struct fdtab_entry));

            return fd;
        }
    }

    // table full
    errno = EMFILE;
    return -1;
}

static struct fdtab_entry *fdtab_get(int fd)
{
    static struct fdtab_entry invalid = {
        .type = FDTAB_TYPE_AVAILABLE,
        .handle = NULL,
        .inherited = 0,
    };

    if (fd < MIN_FD || fd >= MAX_FD) {
        return &invalid;
    } else {
        return &fdtab[fd];
    }
}

static void fdtab_free(int fd)
{
    assert(fd >= MIN_FD && fd < MAX_FD);
    assert(fdtab[fd].type != FDTAB_TYPE_AVAILABLE);
    fdtab[fd].type = FDTAB_TYPE_AVAILABLE;
    fdtab[fd].handle = NULL;
    fdtab[fd].fd = 0;
    fdtab[fd].inherited = 0;
}

// XXX: flags are ignored...
__attribute__((unused)) static int fs_libc_open(char *path, int flags)
{
    ramfs_handle_t vh;
    errval_t err;

    // If O_CREAT was given, we use ramfsfs_create()
    if (flags & O_CREAT) {
        // If O_EXCL was also given, we check whether we can open() first
        if (flags & O_EXCL) {
            err = ramfs_open(mount, path, &vh);
            if (err_is_ok(err)) {
                ramfs_close(mount, vh);
                errno = EEXIST;
                return -1;
            }
            assert(err_no(err) == FS_ERR_NOTFOUND);
        }

        err = ramfs_create(mount, path, &vh);
        if (err_is_fail(err) && err == FS_ERR_EXISTS) {
            err = ramfs_open(mount, path, &vh);
        }
    } else {
        // Regular open()
        err = ramfs_open(mount, path, &vh);
    }

    if (err_is_fail(err)) {
        switch (err_no(err)) {
        case FS_ERR_NOTFOUND:
            errno = ENOENT;
            break;

        default:
            break;
        }

        return -1;
    }

    struct fdtab_entry e = {
        .type = FDTAB_TYPE_FILE,
        .handle = vh,
        .epoll_fd = -1,
    };
    int fd = fdtab_alloc(&e);
    if (fd < 0) {
        ramfs_close(mount, vh);
        return -1;
    } else {
        return fd;
    }
}


static int fat32fs_libc_open(char *path, int flags)
{
    struct fat32fs_handle *vh;
    errval_t err = SYS_ERR_OK;

    domainid_t pid = disp_get_domain_id();

    path = clean_path(path);
    if(path == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    // If O_CREAT was given, we use ramfsfs_create()
    if (flags & O_CREAT) {
        // If O_EXCL was also given, we check whether we can open() first
        if (flags & O_EXCL) {
            err = fat32fs_open(pid, mount, path, flags, &vh);
            if (err_is_ok(err)) {
                fat32fs_handle_close(vh);
                errno = EEXIST;
                return -1;
            }
            assert(err_no(err) == FS_ERR_NOTFOUND);
        }

        err = fat32fs_create(pid, path, flags, &vh);
        if (err_is_fail(err) && err == FS_ERR_EXISTS) {
            err = fat32fs_open(pid, mount, path, flags, &vh);
        }

    } else {
        // Regular open()
        err = fat32fs_open(disp_get_domain_id(), mount, path, flags, &vh);
    }

    if (err_is_fail(err)) {
        switch (err_no(err)) {
        case FS_ERR_NOTFOUND:
            errno = ENOENT;
            break;

        default:
            break;
        }

        return -1;
    }

    struct fdtab_entry e = {
        .type = FDTAB_TYPE_FILE,
        .handle = (void *)vh,
        .epoll_fd = -1,
    };
    int fd = fdtab_alloc(&e);
    if (fd < 0) {
        // we didnt' do any writing, so mode flags can be set to 0
        fat32fs_handle_close(vh);
        return -1;
    } else {
        return fd;
    }
}


__attribute__((unused)) static int fs_libc_read(int fd, void *buf, size_t len)
{
    errval_t err;

    struct fdtab_entry *e = fdtab_get(fd);
    size_t retlen = 0;
    switch (e->type) {
    case FDTAB_TYPE_FILE: {
        ramfs_handle_t fh = e->handle;
        assert(e->handle);
        err = ramfs_read(mount, fh, buf, len, &retlen);
        if (err_is_fail(err)) {
            return -1;
        }
    } break;
    default:
        return -1;
    }

    return retlen;
}

static int fat32fs_libc_read(int fd, void *buf, size_t len)
{
    errval_t err;

    struct fdtab_entry *e = fdtab_get(fd);
    size_t retlen = 0;
    switch (e->type) {
    case FDTAB_TYPE_FILE: {
        struct fat32fs_handle *fh = e->handle;
        assert(e->handle);
        err = fat32fs_read(fh, buf, len, &retlen);
        if (err_is_fail(err)) {
            return -1;
        }
    } break;
    default:
        return -1;
    }

    return retlen;
}

__attribute__((unused)) static int fs_libc_write(int fd, void *buf, size_t len)
{
    struct fdtab_entry *e = fdtab_get(fd);
    if (e->type == FDTAB_TYPE_AVAILABLE) {
        return -1;
    }

    size_t retlen = 0;

    switch (e->type) {
    case FDTAB_TYPE_FILE: {
        ramfs_handle_t fh = e->handle;
        errval_t err = ramfs_write(mount, fh, buf, len, &retlen);
        if (err_is_fail(err)) {
            return -1;
        }
    } break;
    default:
        return -1;
    }

    return retlen;
}


static int fat32fs_libc_write(int fd, void *buf, size_t len)
{
    DEBUG_PRINTF("fwrite len: %zu\n", len);
    struct fdtab_entry *e = fdtab_get(fd);
    if (e->type == FDTAB_TYPE_AVAILABLE) {
        return -1;
    }

    size_t retlen = 0;

    switch (e->type) {
    case FDTAB_TYPE_FILE: {
        struct fat32fs_handle *fh = e->handle;
        errval_t err = fat32fs_write(fh, buf, len, &retlen);
        if (err_is_fail(err)) {
            return -1;
        }
    } break;
    default:
        return -1;
    }

    return retlen;
}

__attribute__((unused)) static int fs_libc_close(int fd)
{
    errval_t err;
    struct fdtab_entry *e = fdtab_get(fd);
    if (e->type == FDTAB_TYPE_AVAILABLE) {
        return -1;
    }

    ramfs_handle_t fh = e->handle;
    switch (e->type) {
    case FDTAB_TYPE_FILE:
        err = ramfs_close(mount, fh);
        if (err_is_fail(err)) {
            return -1;
        }
        break;
    default:
        return -1;
    }

    fdtab_free(fd);
    return 0;
}


static int fat32fs_libc_close(int fd)
{
    struct fdtab_entry *e = fdtab_get(fd);
    if (e->type == FDTAB_TYPE_AVAILABLE) {
        return -1;
    }

    struct fat32fs_handle *fh = e->handle;
    switch (e->type) {
    case FDTAB_TYPE_FILE:
        fat32fs_handle_close(fh);
        break;
    default:
        return -1;
    }

    fdtab_free(fd);
    return 0;
}

__attribute__((unused)) static off_t fs_libc_lseek(int fd, off_t offset, int whence)
{
    struct fdtab_entry *e = fdtab_get(fd);
    ramfs_handle_t fh = e->handle;
    switch (e->type) {
    case FDTAB_TYPE_FILE: {
        enum fs_seekpos fs_whence;
        errval_t err;
        size_t retpos;

        switch (whence) {
        case SEEK_SET:
            fs_whence = FS_SEEK_SET;
            break;

        case SEEK_CUR:
            fs_whence = FS_SEEK_CUR;
            break;

        case SEEK_END:
            fs_whence = FS_SEEK_END;
            break;

        default:
            return -1;
        }

        err = ramfs_seek(mount, fh, fs_whence, offset);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "vfs_seek");
            return -1;
        }

        err = ramfs_tell(mount, fh, &retpos);
        if (err_is_fail(err)) {
            return -1;
        }
        return retpos;
    } break;

    default:
        return -1;
    }
}

static off_t fat32fs_libc_lseek(int fd, off_t offset, int whence)
{
    struct fdtab_entry *e = fdtab_get(fd);
    struct fat32fs_handle *fh = e->handle;
    switch (e->type) {
    case FDTAB_TYPE_FILE: {
        enum fs_seekpos fs_whence;
        errval_t err;
        size_t retpos;

        switch (whence) {
        case SEEK_SET:
            fs_whence = FS_SEEK_SET;
            break;

        case SEEK_CUR:
            fs_whence = FS_SEEK_CUR;
            break;

        case SEEK_END:
            fs_whence = FS_SEEK_END;
            break;

        default:
            return -1;
        }

        err = fat32fs_seek(fh, fs_whence, offset);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "vfs_seek");
            return -1;
        }

        err = fat32fs_tell(fh, &retpos);
        if (err_is_fail(err)) {
            return -1;
        }
        return retpos;
    } break;

    default:
        return -1;
    }
}


__attribute__((unused))
static errval_t fs_mkdir(const char *path)
{
    return ramfs_mkdir(mount, path);
}
__attribute__((unused))
static errval_t fs_rmdir(const char *path)
{
    return ramfs_rmdir(mount, path);
}

__attribute__((unused))
static errval_t fs_rm(const char *path)
{
    return ramfs_remove(mount, path);
}
__attribute__((unused))
static errval_t fs_opendir(const char *path, fs_dirhandle_t *h)
{
    return ramfs_opendir(mount, path, h);
}
__attribute__((unused))
static errval_t fs_readdir(fs_dirhandle_t h, char **name)
{
    return ramfs_dir_read_next(mount, h, name, NULL);
}
__attribute__((unused))
static errval_t fs_closedir(fs_dirhandle_t h)
{
    return ramfs_closedir(mount, h);
}
__attribute__((unused))
static errval_t fs_fstat(fs_dirhandle_t h, struct fs_fileinfo *b)
{
    return ramfs_stat(mount, h, b);
}

static errval_t fat32fs_opendir_glue(const char *path, fs_dirhandle_t *h)
{
    return fat32fs_opendir(disp_get_domain_id(), path, (struct fat32fs_handle **)h);
}

static errval_t fat32fs_mkdir_glue(const char *path)
{
    return fat32fs_mkdir(path);
}

static errval_t fat32fs_rmdir_glue(const char *path)
{
    return fat32fs_rmdir(path);
}

static errval_t fat32fs_fstat_glue(fs_dirhandle_t h, struct fs_fileinfo *b)
{
    return fat32fs_fstat(h, b);
}

static errval_t fat32fs_rm_glue(const char *path)
{
    return fat32fs_rm(path);
}

static errval_t fat32fs_readdir_glue(fs_dirhandle_t h, char **name)
{
    return fat32fs_dir_read_next(h, name, NULL);
}


static errval_t fat32fs_closedir_glue(fs_dirhandle_t h)
{
    // TODO return types
    fat32fs_handle_close(h);
    return SYS_ERR_OK;
}

typedef int fsopen_fn_t(char *, int);
typedef int fsread_fn_t(int, void *buf, size_t);
typedef int fswrite_fn_t(int, void *, size_t);
typedef int fsclose_fn_t(int);
typedef off_t fslseek_fn_t(int, off_t, int);
void newlib_register_fsops__(fsopen_fn_t *open_fn, fsread_fn_t *read_fn,
                             fswrite_fn_t *write_fn, fsclose_fn_t *close_fn,
                             fslseek_fn_t *lseek_fn);

void fs_libc_init(void *fs_mount)
{
    newlib_register_fsops__(fat32fs_libc_open, fat32fs_libc_read, fat32fs_libc_write,
                            fat32fs_libc_close, fat32fs_libc_lseek);

    /* register directory operations */
    fs_register_dirops(fat32fs_mkdir_glue, fat32fs_rmdir_glue, fat32fs_rm_glue, fat32fs_opendir_glue, fat32fs_readdir_glue,
                       fat32fs_closedir_glue, fat32fs_fstat_glue);

    mount = fs_mount;
}
