#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/cache.h>
#include <collections/path_list.h>
#include <fs/fat32.h>
#include <fs/sd.h>

__attribute__((unused)) static inline bool fat32_is_eof(uint32_t fat_entry)
{
    return fat_entry >= 0x0FFFFFF8;
}

__attribute__((unused)) static inline bool fat32_is_free(uint32_t fat_entry)
{
    return fat_entry == 0;
}

__attribute__((unused)) static inline bool fat32_is_bad_cluster(uint32_t fat_entry)
{
    return fat_entry == 0x0FFFFFF7;
}

__attribute__((unused)) static inline bool fat32_dir_is_free(struct fat32_dir_entry *dir)
{
    return dir->Name[0] == 0 || dir->Name[0] == 0xE5;
}

static inline uint32_t fat32_clus2sec(struct fat32 *fs, uint32_t cluster)
{
    return fs->FirstDataSector + (cluster - 2) * fs->SecPerClus;
}

errval_t fat32_read_sector(struct fat32 *fs, uint32_t sector, struct phys_virt_addr *addr){
    return sd_read_sector(fs->sd, sector, addr);
}

errval_t fat32_write_sector(struct fat32 *fs, uint32_t sector, struct phys_virt_addr *addr){
    return sd_write_sector(fs->sd, sector, addr);
}

static inline void fat32_clus2fat_index(struct fat32 *fs, uint32_t cluster,
                                        uint32_t *fat_sector, uint32_t *fat_index)
{
    uint32_t fat_offset = cluster * 4;
    *fat_sector = fs->RsvdSecCnt + (fat_offset / fs->BytesPerSec);
    // uint32_t entries_per_sector = fs->BytesPerSec / 4;
    *fat_index = (fat_offset % fs->BytesPerSec) / 4;
    DEBUG_PRINTF("fat_sector: %d, fat_index: %d\n", *fat_sector, *fat_index);
}

static inline uint32_t fat32_fat_index2cluster(struct fat32 *fs, uint32_t fat_sector,
                                               uint32_t fat_index)
{
    return fat_index + (fat_sector - fs->FirstFatSector) * FAT_ENTRIES_PER_SECTOR(fs);
}

static inline uint32_t fat32_get_fat_entry(struct fat32 *fs, uint32_t cluster)
{
    uint32_t fat_sector, fat_index;
    fat32_clus2fat_index(fs, cluster, &fat_sector, &fat_index);

    // Read FAT sector
    errval_t err = fat32_read_sector(fs, fat_sector, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to read sector in FAT\n");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;
    return fat[fat_index] & 0x0FFFFFFF;
}

static errval_t fat32_set_fat_entry(struct fat32 *fs, uint32_t curr_cluster,
                                    uint32_t new_cluster)
{
    uint32_t fat_sector, fat_index;
    fat32_clus2fat_index(fs, curr_cluster, &fat_sector, &fat_index);
    errval_t err = fat32_read_sector(fs, fat_sector, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to read FAT sector");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;
    uint32_t top_bits = fat[fat_index] & (~0x0FFFFFFF);
    fat[fat_index] = top_bits | new_cluster;
    return fat32_write_sector(fs, fat_sector, &fs->fat_scratch);
}

errval_t init_fat32(struct fat32 *fs)
{
    // init card
    errval_t err = init_sd(&fs->sd);

    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to init sd\n");
        return err;
    }

    err = init_phys_virt_addr(BASE_PAGE_SIZE, &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "init_phys_virt_addr");
        return err;
    }

    err = init_phys_virt_addr(BASE_PAGE_SIZE, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "init_phys_virt_addr");
        return err;
    }

    int j = 0;
    err = fat32_read_sector(fs, j++, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sdhc_read_block");
        return err;
    }

    char *vbuf = (char *)fs->fat_scratch.virt;
    assert(vbuf[0] == 0xEB);
    assert(vbuf[2] == 0x90);
    assert(vbuf[510] == 0x55);
    assert(vbuf[511] == 0xAA);

    // on FAT32 systems, always 0
    uint32_t BPB_RootEntCnt = 0;

    fs->BytesPerSec = *(uint16_t *)(vbuf + FAT32_BPB_BytsPerSec_OFFSET);
    fs->RootDirSectors = (BPB_RootEntCnt * 32) + (fs->BytesPerSec - 1) / fs->BytesPerSec;
    fs->FatSz = *(uint32_t *)(vbuf + FAT32_BPB_FATSz32_OFFSET);
    fs->TotSec = *(uint32_t *)(vbuf + FAT32_BPB_TotSec32_OFFSET);
    fs->NumFATs = *(uint8_t *)(vbuf + FAT32_BPB_NumFATs_OFFSET);
    fs->RsvdSecCnt = *(uint16_t *)(vbuf + FAT32_BPB_RsvdSecCnt_OFFSET);
    fs->SecPerClus = *(uint8_t *)(vbuf + FAT32_BPB_SecPerClus_OFFSET);
    fs->DataSec = fs->TotSec
                  - (fs->RsvdSecCnt + (fs->NumFATs * fs->FatSz) + fs->RootDirSectors);

    fs->CountOfClusters = fs->DataSec / fs->SecPerClus;

    assert(fs->CountOfClusters >= 65525);  // determines type: fat32
    assert(fs->RootDirSectors == 0);

    fs->FirstDataSector = fs->RsvdSecCnt + (fs->NumFATs * fs->FatSz) + fs->RootDirSectors;
    // root dir is at BPB_RootClus
    fs->FirstRootDirCluster = *(uint32_t *)(vbuf + FAT32_BPB_RootClus_OFFSET);
    fs->FirstFatSector = fs->RsvdSecCnt;

    assert(fs->RsvdSecCnt + (fs->NumFATs * fs->FatSz) == fs->FirstDataSector);

    // print all the fields
    DEBUG_PRINTF("BytesPerSec: %d\n", fs->BytesPerSec);
    DEBUG_PRINTF("RootDirSectors: %d\n", fs->RootDirSectors);
    DEBUG_PRINTF("FatSz: %d\n", fs->FatSz);
    DEBUG_PRINTF("TotSec: %d\n", fs->TotSec);
    DEBUG_PRINTF("NumFATs: %d\n", fs->NumFATs);
    DEBUG_PRINTF("RsvdSecCnt: %d\n", fs->RsvdSecCnt);
    DEBUG_PRINTF("SecPerClus: %d\n", fs->SecPerClus);
    DEBUG_PRINTF("DataSec: %d\n", fs->DataSec);
    DEBUG_PRINTF("CountOfClusters: %d\n", fs->CountOfClusters);
    DEBUG_PRINTF("FirstDataSector: %d\n", fs->FirstDataSector);
    DEBUG_PRINTF("FirstRootDirCluster: %d\n", fs->FirstRootDirCluster);
    DEBUG_PRINTF("FirstFatSector: %d\n", fs->FirstFatSector);
    return SYS_ERR_OK;
}

static errval_t fat32_get_free_cluster(struct fat32 *fs, uint32_t *retcluster)
{
    errval_t err;
    // TODO make this work for multiple sectors!

    // load FAT table: first sector
    err = fat32_read_sector(fs, fs->FirstFatSector, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sdhc_read_block");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;

    for (int i = 0; i < FAT_ENTRIES_PER_SECTOR(fs); i++) {
        if (fat32_is_free(fat[i])) {
            // convert entry index to cluster number
            // debug_printf("index %d is free\n", i);
            *retcluster = fat32_fat_index2cluster(fs, fs->FirstFatSector, i);
            return fat32_set_fat_entry(fs, *retcluster, FAT_ENTRY_EOF);
        }
    }
    return FS_ERR_NOTFOUND;
}


/**
 * Assumes data_scratch contains loaded sector with root dir
 *
 */
static errval_t fat32_add_dir_entry(struct fat32 *fs, struct fat32_file *file,
                                    uint32_t dir_sector, uint32_t dir_index,
                                    uint32_t *start_data_cluster,
                                    bool allocate_new_start_data_cluster)
{
    // assumes sector is already loaded
    assert(dir_index < DIR_ENTRIES_PER_SECTOR(fs));
    errval_t err;
    // get a free cluster for content
    uint32_t cluster;

    if (allocate_new_start_data_cluster) {
        err = fat32_get_free_cluster(fs, &cluster);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "fat32_get_free_cluster");
            return err;
        }
    } else {
        cluster = *start_data_cluster;
    }

    err = fat32_read_sector(fs, dir_sector, &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to read dir\n");
    }

    struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt
                                  + dir_index;

    dir->Attr = (uint8_t)file->type;
    dir->FileSize = (file->type != FAT32_FATTR_DIRECTORY) ? file->size : 0;

    dir->FstClusHI = cluster >> 16;
    dir->FstClusLO = cluster & 0xFFFF;

    memcpy(dir->Name, file->name, 11);

    // write file entry to directory!
    err = fat32_write_sector(fs, dir_sector, &fs->data_scratch);

    if (allocate_new_start_data_cluster) {
        *start_data_cluster = cluster;
    }

    return err;
}

static errval_t fat32_zero_cluster(struct fat32 *fs, uint32_t cluster)
{
    uint32_t curr_sector = fat32_clus2sec(fs, cluster);
    memset(fs->data_scratch.virt, 0, fs->BytesPerSec);

    for (uint32_t i = 0; i < fs->SecPerClus; i++) {
        errval_t err = fat32_write_sector(fs, curr_sector + i, &fs->data_scratch);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write sector");
            return err;
        }
    }
    return SYS_ERR_OK;
}

static errval_t fat32_allocate_and_link_cluster(struct fat32 *fs, uint32_t curr_cluster,
                                                uint32_t *new_cluster)
{
    // get a free cluster
    errval_t err = fat32_get_free_cluster(fs, new_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get free cluster");
        return err;
    }

    // link it to the current cluster
    // read fat table entry for the current cluster we're writing
    err = fat32_set_fat_entry(fs, curr_cluster, *new_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set fat entry");
        return err;
    }

    err = fat32_set_fat_entry(fs, *new_cluster, FAT_ENTRY_EOF);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set fat entry of new cluster");
        return err;
    }
    return SYS_ERR_OK;
}

static inline uint32_t fat32_next_data_cluster(struct fat32 *fs, uint32_t curr_cluster)
{
    return fat32_get_fat_entry(fs, curr_cluster);
}

static errval_t fat32_process_dir_at(struct fat32 *fs, uint32_t start_cluster,
                                     uint32_t index, struct fat32_dir_entry *dir,
                                     bool is_read)
{
    // get correct cluster
    uint32_t target_cluster;
    uint32_t byte_offset = index * sizeof(struct fat32_dir_entry);

    errval_t err = fat32_get_cluster_from_offset(fs, start_cluster, byte_offset,
                                                 &target_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get cluster from offset");
        return err;
    }

    uint32_t sector = fat32_clus2sec(fs, target_cluster) + ((byte_offset % BYTES_PER_CLUS(fs)) / fs->BytesPerSec);

    err = fat32_read_sector(fs, sector, &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to read sector");
        return err;
    }

    if (is_read) {
        *dir = *((struct fat32_dir_entry *)fs->data_scratch.virt
                 + (byte_offset % fs->BytesPerSec) / sizeof(struct fat32_dir_entry));
    } else {
        *((struct fat32_dir_entry *)fs->data_scratch.virt
          + (byte_offset % fs->BytesPerSec) / sizeof(struct fat32_dir_entry))
            = *dir;
        err = fat32_write_sector(fs, sector, &fs->data_scratch);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write block");
            return err;
        }
    }

    return SYS_ERR_OK;
}

errval_t fat32_get_dir_at(struct fat32 *fs, uint32_t start_cluster, uint32_t index,
                                 struct fat32_dir_entry *dir)
{
    return fat32_process_dir_at(fs, start_cluster, index, dir, true);
}

errval_t fat32_set_dir_at(struct fat32 *fs, uint32_t start_cluster, uint32_t index,
                                 struct fat32_dir_entry *dir)
{
    return fat32_process_dir_at(fs, start_cluster, index, dir, false);
}

static errval_t fat32_file_exists_in_curr_dir(struct fat32 *fs, uint32_t dir_cluster,
                                              char *fName, bool *res)
{
    errval_t err;
    struct fat32_dir_entry dir;
    uint32_t curr_index = 0;

    while (!fat32_is_eof(dir_cluster)) {
        err = fat32_get_dir_at(fs, dir_cluster, curr_index, &dir);

        if (err_is_fail(err)) {
            // TODO what error?
            DEBUG_ERR(err, "error while getting dir in index\n");
            return err;
        }

        if (memcmp(dir.Name, fName, 11) == 0) {
            *res = true;
            return SYS_ERR_OK;
        }

        if ((++curr_index) % DIR_ENTRIES_PER_CLUSTER(fs) == 0) {
            dir_cluster = fat32_next_data_cluster(fs, dir_cluster);
            curr_index = 0;
        }
    }

    *res = false;
    return SYS_ERR_OK;
}

static errval_t fat32_add_file_to_dir(struct fat32 *fs, uint32_t dir_cluster,
                                      struct fat32_file *file,
                                      uint32_t *ret_start_data_cluster)
{
    // find free spot in dir
    // read dir
    if (fat32_is_eof(dir_cluster) || fat32_is_bad_cluster(dir_cluster)) {
        DEBUG_PRINTF("invalid cluster in add_to_dir\n");
        // TODO: invalid cluster error
        return FS_ERR_NOTFOUND;
    }

    errval_t err;

    bool fexists;
    err = fat32_file_exists_in_curr_dir(fs, dir_cluster, file->name, &fexists);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't check if file exists in dir\n");
        return err;
    }
    if (fexists) {
        DEBUG_PRINTF("file already exists\n");
        return FS_ERR_EXISTS;
    }

    uint32_t dir_sector;
    struct fat32_dir_entry dir;
    uint32_t dir_index = 0;

    while (!fat32_is_eof(dir_cluster)) {
        err = fat32_get_dir_at(fs, dir_cluster, dir_index, &dir);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "couldn't get dir entry");
            return err;
        }
        if (fat32_dir_is_free(&dir)) {
            dir_sector = fat32_clus2sec(fs, dir_cluster)
                         + dir_index / DIR_ENTRIES_PER_SECTOR(fs);
            goto found;
        }
        if ((++dir_index) % DIR_ENTRIES_PER_CLUSTER(fs) == 0) {
            dir_cluster = fat32_next_data_cluster(fs, dir_cluster);
            dir_index = 0;
        }
    }

    DEBUG_PRINTF("no more room in directory, allocating a new cluster!\n");

    // add a new cluster
    err = fat32_allocate_and_link_cluster(fs, dir_cluster, &dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't link a new data cluster to full dir cluster\n");
        return err;
    }

    err = fat32_zero_cluster(fs, dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't zero out the new dir cluster\n");
        return err;
    }
    dir_sector = fat32_clus2sec(fs, dir_cluster);
    dir_index = 0;

found:
    err = fat32_add_dir_entry(fs, file, dir_sector, dir_index, ret_start_data_cluster, true);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't add a new directory entry in fat32_add_file_to_dir\n");
    }

    return err;
}

/**
 * @brief Loads the directory entry of a file in the given directory
 *
 * @param fs FAT32 filesystem
 * @param containing_dir_cluster Cluster to start of containing directory
 * @param name Name fo the entry to load
 * @param ret_dir Copy of the directory entry
 * @return errval_t Success if file exists, else error
 */
errval_t fat32_load_dir_entry_from_name(struct fat32 *fs, uint32_t containing_dir_cluster,
                                        char *name, struct fat32_dir_entry *ret_dir,
                                        uint32_t *ret_cluster, uint32_t *ret_index)
{
    // check if file of that name exists in any of the directory entries
    DEBUG_PRINTF("FAT32: looking for dir entry: \"%.11s\"\n", name);

    errval_t err;
    uint32_t curr_index = 0;
    struct fat32_dir_entry dir;
    while (!fat32_is_eof(containing_dir_cluster)) {
        err = fat32_get_dir_at(fs, containing_dir_cluster, curr_index, &dir);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "couldn't get dir entry");
            return err;
        }

        if (memcmp(dir.Name, name, 11) == 0) {
            if (ret_dir)
                *ret_dir = dir;
            if (ret_cluster)
                *ret_cluster = containing_dir_cluster;
            if (ret_index)
                *ret_index = curr_index;
            return SYS_ERR_OK;
        }

        curr_index++;
        if (curr_index % DIR_ENTRIES_PER_CLUSTER(fs) == 0) {
            containing_dir_cluster = fat32_next_data_cluster(fs, containing_dir_cluster);
            curr_index = 0;
        }
    }

    return FS_ERR_NOTFOUND;
}

errval_t fat32_load_next_dir_entry(struct fat32 *fs, uint32_t first_dir_data_cluster,
                                   uint32_t start_index, struct fat32_dir_entry *ret_dir,
                                   uint32_t *ret_cluster, uint32_t *ret_index)
{
    uint32_t curr_cluster;
    errval_t err = fat32_get_cluster_from_offset(
        fs, first_dir_data_cluster, start_index * sizeof(struct fat32_dir_entry),
        &curr_cluster);
    if (err_is_fail(err)) {
        // TODO error handling
        return FS_ERR_NOTFOUND;
    }

    uint32_t dirent_offset_in_cluster = start_index % DIR_ENTRIES_PER_CLUSTER(fs);
    struct fat32_dir_entry dir;
    while (!fat32_is_eof(curr_cluster)) {
        err = fat32_get_dir_at(fs, curr_cluster, dirent_offset_in_cluster++, &dir);
        if (!fat32_dir_is_free(&dir)) {
            if (ret_dir)
                *ret_dir = dir;
            if (ret_cluster)
                *ret_cluster = curr_cluster;
            if (ret_index)
                *ret_index = start_index;
            return SYS_ERR_OK;
        }

        if (dirent_offset_in_cluster % DIR_ENTRIES_PER_CLUSTER(fs) == 0) {
            curr_cluster = fat32_next_data_cluster(fs, curr_cluster);
            dirent_offset_in_cluster = 0;
        }
        start_index++;
    }

    return FS_ERR_NOTFOUND;
}

/**
 * @brief Moves from the root directory to the given directory
 *
 * @param fs fat32 filesystem
 * @param dir Directory to move in (an absolute path)
 * @param retcluster Cluster containing the target directory
 * @return errval_t
 */
errval_t fat32_move_to_dir(struct fat32 *fs, char *full_path, uint32_t *retcluster)
{
    errval_t err = SYS_ERR_OK;
    uint32_t curr_cluster = fs->FirstRootDirCluster;

    char dir_arr[12];
    char *curr_path_dir = (char *)dir_arr;

    struct path_list_node *path_list = get_path_list(full_path);
    struct path_list_node *curr = path_list;

    while (curr) {
        bool valid = fat32_encode_fname(curr->dir, curr_path_dir);
        if (!valid) {
            DEBUG_PRINTF("invalid name in path\n");
            err = FS_ERR_NOTFOUND;
            goto unwind;
        }

        char *next_file_in_dir = curr_path_dir;
        struct fat32_dir_entry dir_entry;
        err = fat32_load_dir_entry_from_name(fs, curr_cluster, next_file_in_dir,
                                             &dir_entry, NULL, NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "load_dir failed");
            goto unwind;
        }

        curr_cluster = dir_entry.FstClusHI << 16 | dir_entry.FstClusLO;
        curr = curr->next;
    }

    *retcluster = curr_cluster;

unwind:
    if (path_list) {
        free_path_list(path_list);
    }

    return err;
}

errval_t fat32_process_cluster(struct fat32 *fs, uint32_t cluster, uint32_t offset,
                               char *dest_buffer, uint32_t bytes, bool is_read)
{
    errval_t err;
    uint32_t start_sector = fat32_clus2sec(fs, cluster);

    assert(offset + bytes <= BYTES_PER_CLUS(fs));
    uint32_t curr_sector = start_sector + offset / fs->BytesPerSec;

    offset %= fs->BytesPerSec;

    while (bytes > 0) {
        err = fat32_read_sector(fs, curr_sector, &fs->data_scratch);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to read cluster sector\n");
            return err;
        }

        uint32_t bytes_to_copy = MIN(fs->BytesPerSec - offset, bytes);
        if (is_read) {
            memcpy(dest_buffer, fs->data_scratch.virt + offset, bytes_to_copy);
        } else {
            // TODO keep track what part has been written in global state so that error
            // handling is as good as possible
            memcpy(fs->data_scratch.virt + offset, dest_buffer, bytes_to_copy);
            err = fat32_write_sector(fs, curr_sector, &fs->data_scratch);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "couldn't write sector\n");
                return err;
            }
        }
        offset = 0;
        bytes -= bytes_to_copy;
        dest_buffer += bytes_to_copy;
        curr_sector++;
    }
    return SYS_ERR_OK;
}

errval_t fat32_get_cluster_from_offset(struct fat32 *fs, uint32_t start_cluster,
                                       off_t offset, uint32_t *ret_cluster)
{
    uint32_t curr_cluster = start_cluster;
    uint32_t curr_offset = offset;

    while (curr_offset >= BYTES_PER_CLUS(fs)) {
        curr_offset -= BYTES_PER_CLUS(fs);
        curr_cluster = fat32_next_data_cluster(fs, curr_cluster);
        if (fat32_is_eof(curr_cluster)) {
            DEBUG_PRINTF("offset is undefined!\n");
            return FS_ERR_NOTFOUND;
        }
    }

    *ret_cluster = curr_cluster;
    return SYS_ERR_OK;
}

errval_t fat32_write_data(struct fat32 *fs, uint32_t start_cluster,
                          uint32_t cluster_offset, char *src_buffer, uint32_t bytes,
                          uint32_t *ret_last_cluster_written)
{
    errval_t err = SYS_ERR_OK;
    uint32_t prev_cluster, curr_cluster;
    uint32_t bytes_read = 0;

    curr_cluster = prev_cluster = start_cluster;

    while (bytes_read < bytes) {
        uint32_t bytes_to_read = MIN(bytes - bytes_read,
                                     BYTES_PER_CLUS(fs) - cluster_offset);
        err = fat32_process_cluster(fs, curr_cluster, cluster_offset, src_buffer,
                                    bytes_to_read, false);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write cluster\n");
            return err;
        }

        if (bytes_to_read == BYTES_PER_CLUS(fs) - cluster_offset) {
            // cluster is full; set new one
            prev_cluster = curr_cluster;
            curr_cluster = fat32_next_data_cluster(fs, prev_cluster);
            DEBUG_PRINTF("going to next data cluster\n");

            if (fat32_is_eof(curr_cluster)) {
                DEBUG_PRINTF("new cluster allocated and linked\n");
                err = fat32_allocate_and_link_cluster(fs, prev_cluster, &curr_cluster);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "couldn't allocate and link a new data cluster\n");
                    return err;
                }
            }
        }

        bytes_read += bytes_to_read;
        src_buffer += bytes_to_read;
        cluster_offset = 0;
    }

    *ret_last_cluster_written = curr_cluster;

    return SYS_ERR_OK;
}

errval_t fat32_read_data(struct fat32 *fs, uint32_t start_cluster,
                         uint32_t cluster_offset, char *dest_buffer, uint32_t bytes,
                         uint32_t *ret_last_cluster_read)
{
    errval_t err = SYS_ERR_OK;
    uint32_t curr_cluster = start_cluster;
    uint32_t bytes_read = 0;

    while (bytes_read < bytes) {
        uint32_t bytes_to_read = MIN(bytes - bytes_read,
                                     BYTES_PER_CLUS(fs) - cluster_offset);
        err = fat32_process_cluster(fs, curr_cluster, cluster_offset, dest_buffer,
                                    bytes_to_read, true);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to read cluster\n");
            return err;
        }
        if (bytes_to_read == BYTES_PER_CLUS(fs) - cluster_offset) {
            // cluster is full; move to next one
            curr_cluster = fat32_next_data_cluster(fs, curr_cluster);
            DEBUG_PRINTF("reading from next data cluster: %d\n", curr_cluster);
        }

        bytes_read += bytes_to_read;
        dest_buffer += bytes_to_read;
        cluster_offset = 0;
    }
    *ret_last_cluster_read = curr_cluster;

    return SYS_ERR_OK;
}

static errval_t fat32_initialize_dir(struct fat32 *fs, uint32_t containing_dir_cluster,
                                     uint32_t new_dir_cluster, struct fat32_file *file)
{
    errval_t err;
    uint32_t new_dir_sector = fat32_clus2sec(fs, new_dir_cluster);

    err = fat32_zero_cluster(fs, new_dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to zero cluster");
        return err;
    }

    struct fat32_file dot = {
        .name = ".          ", .size = 0, .payload = NULL, .type = FAT32_FATTR_DIRECTORY
    };

    struct fat32_file dotdot = {
        .name = "..         ", .size = 0, .payload = NULL, .type = FAT32_FATTR_DIRECTORY
    };

    err = fat32_add_dir_entry(fs, &dot, new_dir_sector, 0, &new_dir_cluster, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to add dot entry to new dir\n");
        return err;
    }
    err = fat32_add_dir_entry(fs, &dotdot, new_dir_sector, 1, &containing_dir_cluster,
                              false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to add dotdot entry to new dir\n");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t fat32_set_cluster_eof(struct fat32 *fs, uint32_t curr_cluster)
{
    errval_t err;
    uint32_t next_cluster = fat32_get_fat_entry(fs, curr_cluster);

    if (fat32_is_eof(next_cluster)) {
        return SYS_ERR_OK;
    }

    err = fat32_set_fat_entry(fs, curr_cluster, FAT_ENTRY_EOF);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set EOF entry in FAT\n");
        return err;
    }

    curr_cluster = fat32_get_fat_entry(fs, next_cluster);
    return free_cluster_chain(fs, curr_cluster);
}

errval_t fat32_create_empty_file(struct fat32 *fs, const char *path, bool is_dir)
{
    errval_t err;

    char *prefix, *fname;
    split_path(path, &prefix, &fname);

    uint32_t parent_dir_cluster;
    err = fat32_move_to_dir(fs, prefix, &parent_dir_cluster);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "couldn't move into dir\n");
        return err;
    }

    char fat32_short_name[11];
    bool valid = fat32_encode_fname(fname, fat32_short_name);
    if (!valid) {
        DEBUG_PRINTF("Couldn't convert filename to short name: '%s'\n", fname);
        return FS_ERR_INVALID_PATH;
    }

    struct fat32_file file = { .name = fat32_short_name,
                               .size = 0,
                               .payload = NULL,
                               .type = is_dir ? FAT32_FATTR_DIRECTORY : 0 };

    uint32_t start_data_cluster;
    err = fat32_add_file_to_dir(fs, parent_dir_cluster, &file, &start_data_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to write new file entry to dir\n");
        return err;
    }

    if (is_dir) {
        err = fat32_initialize_dir(fs, parent_dir_cluster, start_data_cluster, &file);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to initialize dir\n");
            return err;
        }
    }

    return SYS_ERR_OK;
}

errval_t free_cluster_chain(struct fat32 *fs, uint32_t start_data_cluster)
{
    uint32_t curr_cluster = start_data_cluster;
    while (!fat32_is_free(curr_cluster)) {
        uint32_t next_cluster = fat32_get_fat_entry(fs, curr_cluster);
        errval_t err = fat32_set_fat_entry(fs, curr_cluster, FAT_ENTRY_FREE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to set free entry in FAT\n");
            return err;
        }
        if (fat32_is_eof(next_cluster)) {
            break;
        }
        curr_cluster = next_cluster;
    }

    return SYS_ERR_OK;
}

errval_t fat32_delete_file(struct fat32 *fs, uint32_t dir_cluster, uint32_t index)
{
    // load sector
    errval_t err;

    // get entry
    struct fat32_dir_entry dir;
    err = fat32_get_dir_at(fs, dir_cluster, index, &dir);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get dir entry\n");
        return err;
    }
    uint32_t data_cluster = dir.FstClusHI << 16 | dir.FstClusLO;

    dir.Name[0] = FAT32_FNAME_FREE;
    err = fat32_set_dir_at(fs, dir_cluster, index, &dir);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set dir entry\n");
        return err;
    }

    err = free_cluster_chain(fs, data_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't free data of deleted file!\n");
        return err;
    }

    return SYS_ERR_OK;
}

bool fat32_is_dir_empty(struct fat32 *fs, uint32_t start_data_cluster)
{
    // TODO return types
    errval_t err;
    // skip dot and dotdot files!
    err = fat32_load_next_dir_entry(fs, start_data_cluster, 2, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        return true;
    }

    return false;
}