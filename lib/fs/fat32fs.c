#include <aos/aos.h>

#include <fs/fat32fs.h>
#include <fs/fat32.h>
#include <collections/hash_table.h>
#include <collections/path_list.h>
#include <fcntl.h>


static fileref_id_t get_new_fid(void)
{
    while (collections_hash_find(fs_state.fid2handle, ++fs_state.curr_fid_counter))
        ;
    return fs_state.curr_fid_counter++;
}

void fat32fs_add_file_handler(domainid_t pid, struct fat32fs_handle *handle)
{
    fileref_id_t fid = get_new_fid();
    handle->fid = fid;
    handle->pid = pid;
    collections_hash_insert(fs_state.fid2handle, fid, handle);

    // TODO return type?
    int pathlen = strlen(handle->path);

    struct handle_list_node *node = malloc(sizeof(struct handle_list_node));
    node->handle = handle;

    struct handle_list_node *old_head = hashmap_get(&fs_state.path2handle, handle->path,
                                                    pathlen);
    if (!old_head) {
        node->next = NULL;
    } else {
        node->next = old_head;
    }
    hashmap_remove(&fs_state.path2handle, handle->path, pathlen);
    hashmap_put(&fs_state.path2handle, handle->path, pathlen, node);

    assert(hashmap_get(&fs_state.path2handle, handle->path, pathlen));
}

struct fat32fs_handle *handle_open(domainid_t pid, struct fat32fs_dirent *d,
                                   const char *path)
{
    struct fat32fs_handle *h = calloc(1, sizeof(*h));
    if (h == NULL) {
        DEBUG_PRINTF("couldnt alloce a file handle\n");
        return NULL;
    }
    h->dirent = d;
    h->curr_data_cluster = d->start_data_cluster;
    h->path = strdup(path);

    fat32fs_add_file_handler(pid, h);

    return h;
}

void  fat32fs_update_all_handles_to(const char *path, uint32_t max_offset){
    // get head of all handles with this path and iterate through them
    // whenever a handle has a offset that's too high, update it
    struct handle_list_node *node = hashmap_get(&fs_state.path2handle, path, strlen(path));
    assert(node);
    assert(!node->handle->dirent->is_dir);
    while (node) {
        struct fat32fs_handle *handle = node->handle;
        handle->dirent->size = max_offset;
        if (handle->u.file_offset > max_offset) {
            handle->u.file_offset = max_offset;
            // set the current cluster to the last cluster of the file
            fat32_get_cluster_from_offset(&fs_state.fat32, handle->dirent->start_data_cluster, max_offset, &handle->curr_data_cluster);
        }
        node = node->next;
    }
}

__attribute__((unused)) static void fat32fs_truncate(struct fat32fs_handle *h)
{
    DEBUG_PRINTF("truncating\n");
    fat32_set_cluster_eof(&fs_state.fat32, h->curr_data_cluster);
    struct fat32_dir_entry dir;
    fat32_get_dir_at(&fs_state.fat32, h->dirent->dir_cluster, h->dirent->dir_index, &dir);
    dir.FileSize = h->u.file_offset;
    fat32_set_dir_at(&fs_state.fat32, h->dirent->dir_cluster, h->dirent->dir_index, &dir);


    // find all open handles to same file and update their offsets if they 
    // are past the truncated point

    fat32fs_update_all_handles_to(h->path, h->u.file_offset);
    DEBUG_PRINTF("new fsize: %u\n", h->dirent->size);

}

void fat32fs_handle_close(struct fat32fs_handle *h)
{
    // check if we need to truncate the rest of the file
    if (h->flags & (O_RDWR | O_WRONLY)) {
        if (h->u.file_offset != h->dirent->size) {
            // TODO earlier: did truncate here
        }
    }

    // write back new size TODO
    //struct fat32_dir_entry dir;
    //fat32_get_dir_at(&fs_state.fat32, h->dirent->dir_cluster, h->dirent->dir_index, &dir);
    //dir.FileSize = MAX(h->u.file_offset, h->dirent->size);
    //fat32_set_dir_at(&fs_state.fat32, h->dirent->dir_cluster, h->dirent->dir_index, &dir);
    collections_hash_delete(fs_state.fid2handle, h->fid);
    // TODO return type

    struct handle_list_node *head = hashmap_get(&fs_state.path2handle, h->path,
                                                strlen(h->path));
    assert(head); 
    if(head->next == NULL){
        // remove all the entries
        hashmap_remove(&fs_state.path2handle, h->path, strlen(h->path));
        free(head);
    }else{
        struct handle_list_node *curr = head;
        while(curr->next != NULL){
            if(curr->next->handle == h){
                struct handle_list_node *to_delete = curr->next;
                curr->next = curr->next->next;
                free(to_delete);
                break;
            }
            curr = curr->next;
        }
    }
                 
    free(h->path);
    free(h->dirent);
}

static errval_t resolve_path(domainid_t pid, const char *path,
                             struct fat32fs_handle **ret_fh)
{
    errval_t err = SYS_ERR_OK;

    struct fat32_dir_entry dir;
    uint32_t sector, index, parent_dir_cluster;

    struct fat32fs_dirent *dirent = calloc(1, sizeof(struct fat32fs_dirent));
    char *path_prefix, *fname = NULL;
    if(strncmp(path, "/", 2) == 0){
        dirent->dir_cluster = fs_state.fat32.FirstRootDirCluster;
        dirent->dir_index = 0;

        dirent->start_data_cluster = fs_state.fat32.FirstRootDirCluster;
        fname = strdup(".          ");
        dirent->name = fname;

        dirent->size = dir.FileSize;
        dirent->is_dir = true;
    }else{
        split_path(path, &path_prefix, &fname);

        err = fat32_move_to_dir(&fs_state.fat32, path_prefix, &parent_dir_cluster);

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "fat32_move_to_dir failed");
            goto unwind_split;
        }

        char fat32_name[11];
        bool valid = fat32_encode_fname(fname, fat32_name);

        if (!valid) {
            // TODO better error
            err = FS_ERR_NOTFOUND;
            goto unwind;
        }


        err = fat32_load_dir_entry_from_name(&fs_state.fat32, parent_dir_cluster, fat32_name,
                                            &dir, &sector, &index);

        if (err_is_fail(err)) {
            goto unwind;
        }

        dirent->dir_cluster = parent_dir_cluster;
        dirent->dir_index = index;

        dirent->start_data_cluster = dir.FstClusHI << 16 | dir.FstClusLO;
        dirent->name = fname;

        dirent->size = dir.FileSize;
        dirent->is_dir = (dir.Attr == FAT32_FATTR_DIRECTORY);

    }

    if (ret_fh) {

        struct fat32fs_handle *fh = handle_open(pid, dirent, path);

        if (fh == NULL) {
            err = LIB_ERR_MALLOC_FAIL;
            goto unwind;
        }

        *ret_fh = fh;

        goto success;
    } else {
        free(dirent);
        goto success;
    }
unwind:
    free(dirent);
unwind_split:
    free(fname);
    free(path_prefix);
success:
    return err;
}

// assumes path is clean
errval_t fat32fs_open(domainid_t pid, struct fat32fs_mount *mount, const char *path,
                      int flags, struct fat32fs_handle **rethandle)
{
    errval_t err;

    struct fat32fs_handle *handle;
    err = resolve_path(pid, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }

    if (handle->dirent->is_dir) {
        fat32fs_handle_close(handle);
        return FS_ERR_NOTFILE;
    }

    handle->flags = flags;


    // TODO
    // truncate if flags match
    if (handle->flags & O_TRUNC) {
        fat32fs_truncate(handle);
    }

    *rethandle = handle;

    return SYS_ERR_OK;
}

errval_t fat32fs_read(struct fat32fs_handle *h, void *buffer, size_t bytes,
                      size_t *bytes_read)
{
    if (h->dirent->is_dir) {
        return FS_ERR_NOTFILE;
    }

    if (h->dirent->size < h->u.file_offset) {
        bytes = 0;
    } else if (h->u.file_offset + bytes > h->dirent->size) {
        bytes = h->dirent->size - h->u.file_offset;
        assert(h->u.file_offset + bytes == h->dirent->size);
    }
    // DEBUG_PRINTF("offset: %d, size: %d, bytes: %d\n", h->u.file_offset,
    // h->dirent->size, bytes);

    uint32_t new_data_cluster;
    // read bytes into it
    // TODO what if read fails in between? Keep updating the file offset after every read
    errval_t err = fat32_read_data(
        &fs_state.fat32, h->curr_data_cluster,
        h->u.file_offset % (fs_state.fat32.BytesPerSec * fs_state.fat32.SecPerClus),
        (char *)buffer, bytes, &new_data_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "fat32_read_data failed");
        return err;
    }
    h->curr_data_cluster = new_data_cluster;
    h->u.file_offset += bytes;
    *bytes_read = bytes;

    return SYS_ERR_OK;
}


errval_t fat32fs_write(struct fat32fs_handle *h, const void *buf, size_t bytes,
                       size_t *bytes_written)
{
    if (bytes == 0) {
        return SYS_ERR_OK;
    }

    if (h->dirent->is_dir) {
        return FS_ERR_NOTFILE;
    }

    uint32_t new_data_cluster;
    errval_t err = fat32_write_data(
        &fs_state.fat32, h->curr_data_cluster,
        h->u.file_offset % (fs_state.fat32.BytesPerSec * fs_state.fat32.SecPerClus),
        (char *)buf, bytes, &new_data_cluster);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "fat32_write_data failed");
        return err;
    }

    if (bytes_written) {
        *bytes_written = bytes;
    }

    h->curr_data_cluster = new_data_cluster;
    h->u.file_offset += bytes;

    if (h->u.file_offset >= h->dirent->size) {
        h->dirent->size = h->u.file_offset;
        struct fat32_dir_entry dir;
        err = fat32_get_dir_at(&fs_state.fat32, h->dirent->dir_cluster,
                               h->dirent->dir_index, &dir);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't get file entry\n");
            return err;
        }
        dir.FileSize = h->dirent->size;
        err = fat32_set_dir_at(&fs_state.fat32, h->dirent->dir_cluster,
                               h->dirent->dir_index, &dir);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't update dir entry filesize\n");
            return err;
        }
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_seek(struct fat32fs_handle *h, enum fs_seekpos whence, off_t offset)
{
    errval_t err;

    switch (whence) {
    case FS_SEEK_SET:
        assert(offset >= 0);
        if (h->dirent->is_dir) {
            h->u.dir_offset = 0;
            h->curr_data_cluster = h->dirent->start_data_cluster;
            while (offset-- > 0) {
                err = fat32fs_dir_read_next(h, NULL, NULL);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "couldn't seek next dir entry\n");
                    return err;
                }
            }
        } else {
            uint32_t new_data_cluster;
            err = fat32_get_cluster_from_offset(&fs_state.fat32,
                                                h->dirent->start_data_cluster, offset,
                                                &new_data_cluster);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "couldn't seek to position\n");
                return err;
            }
            h->curr_data_cluster = new_data_cluster;
            h->u.file_offset = offset;
        }
        break;

    case FS_SEEK_CUR:
        if (h->dirent->is_dir) {
            // ramfs doesn't implement this
            assert(!"NYI");
        } else {
            assert(offset >= 0 || -offset <= h->u.file_offset);
            uint32_t start_data_cluster;

            // if we need to go to a previous cluster in chain, then
            // start from first file cluster, else continue from current cluster
            uint32_t bytes_per_clus = fs_state.fat32.BytesPerSec
                                      * fs_state.fat32.SecPerClus;
            uint32_t goal_clus_idx = (h->u.file_offset + offset) / bytes_per_clus;
            uint32_t curr_clus_idx = h->u.file_offset / bytes_per_clus;
            if (goal_clus_idx < curr_clus_idx) {
                offset = h->u.file_offset + offset;
                start_data_cluster = h->dirent->start_data_cluster;
            } else {
                start_data_cluster = h->curr_data_cluster;
            }

            err = fat32_get_cluster_from_offset(&fs_state.fat32, start_data_cluster,
                                                offset, &h->curr_data_cluster);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "couldn't seek to position\n");
                return err;
            }
            h->u.file_offset += offset;
        }

        break;

    case FS_SEEK_END:
        if (h->dirent->is_dir) {
            // ramfs doesn't implement this,
            assert(!"NYI");
        } else {
            // TODO what is going on here? need to resize?
            assert(offset >= 0 || -offset <= h->dirent->size);
            h->u.file_offset = h->dirent->size + offset;
            // TODO BUG
        }
        break;

    default:
        USER_PANIC("invalid whence argument to fat32fs seek");
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_tell(struct fat32fs_handle *h, uint32_t *pos)
{
    if (h->dirent->is_dir) {
        // TODO is this correct?
        *pos = 0;
    } else {
        *pos = h->u.file_offset;
    }
    return SYS_ERR_OK;
}

// assumes path is clean
errval_t fat32fs_create(domainid_t pid, char *path, int flags,
                        struct fat32fs_handle **rethandle)
{
    errval_t err;

    err = resolve_path(pid, path, NULL);
    if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    }

    err = fat32_create_empty_file(&fs_state.fat32, path, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not create file\n");
        return err;
    }

    if (rethandle) {
        err = fat32fs_open(pid, NULL, path, flags, rethandle);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to open file after creation\n");
            return err;
        }
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_rm(const char *path)
{
    errval_t err = SYS_ERR_OK;

    path = clean_path(path);
    if (path == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    struct fat32fs_handle *h;
    err = resolve_path(0, path, &h);
    if (err_is_fail(err) && err == FS_ERR_NOTFOUND) {
        return err;
    }

    if (h->dirent->is_dir) {
        err = FS_ERR_NOTFILE;
        goto unwind;
    }

    err = fat32_delete_file(&fs_state.fat32, h->dirent->dir_cluster, h->dirent->dir_index);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't delete file\n");
        goto unwind;
    }

unwind:
    fat32fs_handle_close(h);
    return err;
}


errval_t fat32fs_mkdir(const char *path)
{
    errval_t err = resolve_path(0, path, NULL);

    if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    }

    err = fat32_create_empty_file(&fs_state.fat32, path, true);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not create directory\n");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_fstat(struct fat32fs_handle *h, struct fs_fileinfo *b)
{
    b->size = h->dirent->size;
    b->type = h->dirent->is_dir ? FS_DIRECTORY : FS_FILE;
    return SYS_ERR_OK;
}


errval_t fat32fs_rmdir(const char *path)
{
    errval_t err;

    path = clean_path(path);

    struct fat32fs_handle *handle;
    err = resolve_path(0, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }

    if (!handle->dirent->is_dir) {
        err = FS_ERR_NOTDIR;
        goto out;
    }

    assert(handle->dirent->is_dir);

    // check first if dir contains anything
    // can only delete empty directories!
    bool is_empty = fat32_is_dir_empty(&fs_state.fat32,
                                       handle->dirent->start_data_cluster);

    if (!is_empty) {
        err = FS_ERR_NOTEMPTY;
        DEBUG_ERR(err, "couldn't delete non-empty directory\n");
        goto out;
    }


    err = fat32_delete_file(&fs_state.fat32, handle->dirent->dir_cluster,
                            handle->dirent->dir_index);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "couldn't delete directory\n");
        goto out;
    }

out:
    fat32fs_handle_close(handle);
    return err;
}

errval_t fat32fs_opendir(domainid_t pid, const char *path,
                         struct fat32fs_handle **rethandle)
{
    struct fat32fs_handle *handle;
    errval_t err = resolve_path(pid, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }

    if (!handle->dirent->is_dir) {
        fat32fs_handle_close(handle);
        return FS_ERR_NOTDIR;
    }

    handle->flags = 0;
    handle->u.dir_offset = 0;

    *rethandle = handle;

    return SYS_ERR_OK;
}

errval_t fat32fs_dir_read_next(struct fat32fs_handle *h, char **retname,
                               struct fs_fileinfo *info)
{
    if (!h->dirent->is_dir) {
        return FS_ERR_NOTDIR;
    }

    // read at current index
    struct fat32_dir_entry dirent;
    uint32_t dirent_cluster, dirent_index;
    errval_t err = fat32_load_next_dir_entry(
        &fs_state.fat32, h->dirent->start_data_cluster, h->u.dir_offset, &dirent,
        &dirent_cluster, &dirent_index);
    if (err_is_fail(err)) {
        // TODO always?
        return FS_ERR_INDEX_BOUNDS;
    }

    if (retname != NULL) {
        *retname = malloc(12);
        fat32_decode_fname((char *)dirent.Name, *retname);
    }

    if (info != NULL) {
        info->type = (dirent.Attr == FAT32_FATTR_DIRECTORY) ? FS_DIRECTORY : FS_FILE;
        info->size = dirent.FileSize;
    }

    h->u.dir_offset = dirent_index + 1;
    h->curr_data_cluster = dirent_cluster;

    return SYS_ERR_OK;
}

void fs_init(void)
{
    fs_state.curr_fid_counter = 0;

    collections_hash_create(&fs_state.fid2handle, free);
    errval_t err = init_fat32(&fs_state.fat32);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to initialize filesystem!\n");
    }
    hashmap_create(8, &fs_state.path2handle);
    thread_mutex_init(&fs_state.mutex);
}

void fat32fs_mount(char *path){
    fs_mount.path = path;
}