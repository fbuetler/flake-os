#include <aos/aos.h>

#include <fs/fat32fs.h>
#include <fs/fat32.h>
#include <collections/hash_table.h>

struct fs_state fs_state;
collections_hash_table *fs_file_handles;

static fileref_id_t get_new_fid(void)
{
    // TODO will loop endlessly if all is full
    while (collections_hash_find(fs_file_handles, ++fs_state.curr_fid_counter))
        ;
    return fs_state.curr_fid_counter++;
}

void fat32fs_add_file_handler(domainid_t pid, struct fat32fs_handle *handle)
{
    fileref_id_t fid = get_new_fid();
    handle->fid = fid;
    handle->pid = pid;
    collections_hash_insert(fs_file_handles, fid, handle);
}

struct fat32fs_handle *handle_open(domainid_t pid, struct fat32fs_dirent *d)
{
    struct fat32fs_handle *h = calloc(1, sizeof(*h));
    if (h == NULL) {
        return NULL;
    }
    h->dirent = d;
    h->curr_data_cluster = d->start_data_cluster;

    fat32fs_add_file_handler(pid, h);
    return h;
}

void fat32fs_handle_close(struct fat32fs_handle *h)
{
    collections_hash_delete(fs_file_handles, h->fid);
}

static void split_path(const char *full_path, char **path_prefix, char **fname)
{
    // TODO malloc fail
    uint32_t last_separator = get_path_dir_prefix(full_path);
    if (last_separator == -1) {
        *path_prefix = strdup("");
        *fname = strdup(full_path);
    } else {
        int full_path_len = strlen(full_path);
        *path_prefix = malloc(last_separator + 1);
        *fname = malloc(full_path_len - last_separator + 1);

        memcpy(*path_prefix, full_path, last_separator);
        (*path_prefix)[last_separator] = '\0';
        memcpy(*fname, full_path + last_separator + 1, full_path_len - last_separator + 1);
    }
}

static errval_t resolve_path(domainid_t pid, const char *path,
                             struct fat32fs_handle **ret_fh)
{
    errval_t err = SYS_ERR_OK;

    struct fat32_dir_entry dir;
    uint32_t sector, index, parent_dir_cluster;

    char *path_prefix, *fname;
    split_path(path, &path_prefix, &fname);
    err = move_to_dir(&fs_state.fat32, path_prefix, &parent_dir_cluster);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "move_to_dir failed");
        goto unwind_split;
    }

    struct fat32fs_dirent *dirent = calloc(1, sizeof(struct fat32fs_dirent));
    char fat32_name[11];
    bool valid = to_fat32_short_name(fname, fat32_name);

    if(!valid){
        // TODO better error
        err = FS_ERR_NOTFOUND;
        goto unwind;
    }

    err = load_dir_entry_from_name(&fs_state.fat32, parent_dir_cluster, fat32_name, &dir, &sector,
                                   &index);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "load_dir_entry_from_name failed");
        goto unwind;
    }

    dirent->dir_sector = sector;
    dirent->dir_index = index;

    dirent->start_data_cluster = dir.FstClusHI << 16 | dir.FstClusLO;
    dirent->name = fname;

    dirent->size = dir.FileSize;
    dirent->is_dir = (dir.Attr == FAT32_FATTR_DIRECTORY);


    if (ret_fh) {
        struct fat32fs_handle *fh = handle_open(pid, dirent);
        if (fh == NULL) {
            err = LIB_ERR_MALLOC_FAIL;
            goto unwind;
        }
        fh->path = path_prefix;
        *ret_fh = fh;
    }
unwind:
    free(dirent);
unwind_split:
    free(fname);
    free(path_prefix);
    return err;
}

errval_t fat32fs_open(domainid_t pid, struct fat32fs_mount *mount, const char *path,
                             struct fat32fs_handle **rethandle)
{
    errval_t err;

    struct fat32fs_handle *handle;
    DEBUG_PRINTF("before resolve path of path: %s\n", path);
    err = resolve_path(pid, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_PRINTF("after path resolve\n");

    if (handle->dirent->is_dir) {
        fat32fs_handle_close(handle);
        return FS_ERR_NOTFILE;
    }

    *rethandle = handle;

    return SYS_ERR_OK;
}

errval_t fat32fs_read(void *st, struct fat32fs_handle *h, void *buffer,
                             size_t bytes, size_t *bytes_read)
{
    if (h->dirent->is_dir) {
        return FS_ERR_NOTFILE;
    }

    if(h->dirent->size < h->u.file_offset){
        bytes = 0;
    }else if (h->u.file_offset + bytes > h->dirent->size) {
        bytes = h->dirent->size - h->u.file_offset;
        assert(h->u.file_offset + bytes == h->dirent->size);
    }

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

void fs_init(void)
{
    fs_state.curr_fid_counter = 0;

    collections_hash_create(&fs_file_handles, free);
    errval_t err = init_fat32(&fs_state.fat32);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to initialize filesystem!\n");
    }
}
