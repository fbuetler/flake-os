/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/deferred.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/cache.h>

#include <fs/fat32.h>

void *sd_mem_base;

static inline lpaddr_t shdc_get_phys_addr(void *addr)
{
    size_t offset = (size_t)addr - (size_t)sd_mem_base;

    size_t phys_base = IMX8X_SDHC2_BASE;
    return (lpaddr_t)(phys_base + offset);
}

struct path_list_node *init_new_path_list_node(char *dir, struct path_list_node *prev)
{
    struct path_list_node *node = malloc(sizeof(struct path_list_node));
    node->dir = dir;
    node->next = NULL;
    node->prev = prev;
    return node;
}

void free_path_list(struct path_list_node *head)
{
    struct path_list_node *node = head;
    while (node != NULL) {
        struct path_list_node *next = node->next;
        free(node);
        node = next;
    }
}

struct path_list_node *get_path_list(char *orig_path)
{
    // copy path
    int N = strlen(orig_path);
    char *path = malloc(N + 1);
    memcpy(path, orig_path, N + 1);

    char *separator = "/";
    char *token = strtok(path, separator);

    if (!token) {
        // either no delimiter exists, or the path is empty, or the path
        // consists entirely of delimiters.

        if (*path == separator[0] || *path == 0) {
            free(path);
            return NULL;
        } else {
            free(path);
            return init_new_path_list_node(path, NULL);
        }
    }

    struct path_list_node *head = init_new_path_list_node(token, NULL);
    struct path_list_node *curr = head;
    while ((token = strtok(NULL, separator)) != NULL) {
        if (memcmp(token, ".", 2) == 0) {
            continue;
        } else if (memcmp(token, "..", 3) == 0) {
            if (curr->prev) {
                struct path_list_node *prev = curr->prev;
                free(curr);
                curr = prev;
                curr->next = NULL;
            }
            continue;
        }

        struct path_list_node *node = init_new_path_list_node(token, curr);
        curr->next = node;
        curr = node;
    }

    free(path);
    return head;
}

__attribute__((unused)) static inline bool fat_entry_is_eof(uint32_t fat_entry)
{
    return fat_entry >= 0x0FFFFFF8;
}

__attribute__((unused)) static inline bool fat_entry_is_free(uint32_t fat_entry)
{
    return fat_entry == 0;
}

__attribute__((unused)) static inline bool fat_entry_is_bad_cluster(uint32_t fat_entry)
{
    return fat_entry == 0x0FFFFFF7;
}

__attribute__((unused)) static inline bool dir_is_free(struct fat32_dir_entry *dir)
{
    return dir->Name[0] == 0 || dir->Name[0] == 0xE5;
}

static inline bool valid_fat32_fname_char(char c, int index_in_fname)
{
    if (c == 0x05 && index_in_fname == 0) {
        return true;
    }

    if (c == 0x20 && index_in_fname == 0) {
        return false;
    }

    if (c < 0x20) {
        return false;
    }

    switch (c) {
    case 0x22:
    case 0x2A:
    case 0x2B:
    case 0x2C:
    case 0x2E:
    case 0x2F:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x7C:
        return false;
    default:
        return true;
    }
}

bool to_fat32_short_name(char *old, char *new_name)
{
    int N = strlen(old);
    if (N > 12) {
        return false;
    }

    if (N == 0) {
        return false;
    }

    if (old[0] == '.') {
        if (N == 1) {
            memcpy(new_name, ".          ", 11);
            return true;
        } else if (N == 2 && old[1] == '.') {
            memcpy(new_name, "..         ", 11);
            return true;
        }
    }


    // TODO needs an alphanumeric?

    char candidate[12];
    memset(candidate, 0x20, 12);

    memcpy(candidate, old, N);


    memset(new_name, 0x20, 11);


    // check if there is a dot in the name
    int dot_position = -1;
    for (int i = N - 1; i >= 1; i--) {
        if (candidate[i] == '.') {
            dot_position = i;
            candidate[i] = 0x20;
            break;
        }
    }

    if (dot_position == -1 && N > 11) {
        return false;
    }

    // to uppercase & validate each char
    for (int i = 0; i < N; i++) {
        candidate[i] = (char)toupper(candidate[i]);
        if (!valid_fat32_fname_char(candidate[i], i)) {
            DEBUG_PRINTF("invalid char: %c\n", candidate[i]);
            return false;
        }
    }

    // copy everything from the last dot to the end
    if (dot_position != -1) {
        // TODO: what if extension is too long or multiple dots?
        assert(N - dot_position - 1 <= 3);

        int chars_after_dot = N - dot_position - 1;
        memcpy(new_name + 8, candidate + dot_position + 1, chars_after_dot);
        memcpy(new_name, candidate, dot_position);
    } else {
        memcpy(new_name, candidate, N);
    }

    return true;
}

errval_t fs_read_sector(struct fat32 *fs, uint32_t sector, struct phys_virt_addr *addr)
{
    if (addr->last_sector == sector) {
        return SYS_ERR_OK;
    } else {
        addr->last_sector = sector;
    }
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    return sdhc_read_block(fs->sd, sector, addr->phys);
}

errval_t fs_write_sector(struct fat32 *fs, uint32_t sector, struct phys_virt_addr *addr)
{
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    errval_t res = sdhc_write_block(fs->sd, sector, addr->phys);
    // TODO both cache flushes aren't necessary
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    addr->last_sector = sector;
    return res;
}

static inline uint32_t clus2sec(struct fat32 *fs, uint32_t cluster)
{
    return fs->FirstDataSector + (cluster - 2) * fs->SecPerClus;
}


static inline void clus2fat_index(struct fat32 *fs, uint32_t cluster,
                                     uint32_t *fat_sector, uint32_t *fat_index)
{
    uint32_t fat_offset = cluster * 4;
    *fat_sector = fs->RsvdSecCnt + (fat_offset / fs->BytesPerSec);
    // uint32_t entries_per_sector = fs->BytesPerSec / 4;
    *fat_index = (fat_offset % fs->BytesPerSec) / 4;
    DEBUG_PRINTF("fat_sector: %d, fat_index: %d\n", *fat_sector, *fat_index);
}

static inline uint32_t fat_index2cluster(struct fat32 *fs, uint32_t fat_sector,
                                         uint32_t fat_index)
{
    return fat_index + (fat_sector - fs->FirstFatSector) * FAT_ENTRIES_PER_SECTOR(fs);
}

static inline uint32_t get_fat_entry(struct fat32 *fs, uint32_t cluster)
{
    uint32_t fat_sector, fat_index;
    clus2fat_index(fs, cluster, &fat_sector, &fat_index);

    // Read FAT sector
    errval_t err = fs_read_sector(fs, fat_sector, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to read sector in FAT\n");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;
    /*for (int i = 0; i < 128; i++) {
        printf("%d: %lx\n", i, fat[i] & 0x0FFFFFFF);
    }*/
    return fat[fat_index] & 0x0FFFFFFF;
}

static errval_t set_fat_entry(struct fat32 *fs, uint32_t curr_cluster,
                              uint32_t new_cluster)
{
    uint32_t fat_sector, fat_index;
    clus2fat_index(fs, curr_cluster, &fat_sector, &fat_index);
    errval_t err = fs_read_sector(fs, fat_sector, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to read FAT sector");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;
    // TODO top bits need to be kept
    fat[fat_index] = new_cluster;
    return fs_write_sector(fs, fat_sector, &fs->fat_scratch);
}

void print_file(struct fat32 *fs, uint32_t cluster, uint32_t size)
{
    while (size) {
        uint32_t fat_sector, fat_index;
        clus2fat_index(fs, cluster, &fat_sector, &fat_index);

        // Read FAT sector
        fs_read_sector(fs, fat_sector, &fs->fat_scratch);
        uint32_t new_cluster = *((uint32_t *)fs->fat_scratch.virt + fat_index)
                               & 0x0FFFFFFF;

        uint32_t cluster_start_sector = clus2sec(fs, cluster);

        for (uint32_t curr_sector = cluster_start_sector;
             curr_sector < cluster_start_sector + fs->SecPerClus && size; curr_sector++) {
            // read sector
            fs_read_sector(fs, curr_sector, &fs->data_scratch);

            // print sector
            uint8_t *sector = fs->data_scratch.virt;
            for (int i = 0; (i < fs->BytesPerSec) && size > 0; i++) {
                printf("%c", sector[i]);
                size--;
            }
        }

        cluster = new_cluster;
    }
}

errval_t init_sd(struct sdhc_s **sd)
{
    struct capref devframe_cap = (struct capref) {
        .cnode = cnode_arg,
        .slot = ARGCN_SLOT_DEVFRAME,
    };

    size_t devframe_bytes;
    genpaddr_t devframe_base;
    errval_t err = get_phys_addr(devframe_cap, &devframe_base, &devframe_bytes);

    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to get phys addr of devframe\n");
        return err;
    }

    err = paging_map_frame_attr(get_current_paging_state(), &sd_mem_base, devframe_bytes,
                                devframe_cap, VREGION_FLAGS_READ_WRITE_NOCACHE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to map dev frame");
        return err;
    }
    if ((void *)sd_mem_base == NULL) {
        USER_PANIC("FS: No register region mapped \n");
    }

    DEBUG_PRINTF("initializing sdhc... \n");
    err = sdhc_init(sd, sd_mem_base);
    DEBUG_PRINTF("sdhc initialized\n");

    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to initialize sdhc\n");
        return err;
    }

    return SYS_ERR_OK;
}


/*
    Experimantal Function: read contents of root directory
*/
__attribute__((unused)) static errval_t read_root_dir(struct fat32 *fs,
                                                      struct phys_virt_addr *scratch)
{
    uint32_t root_dir_sector = fs->FirstRootDirCluster;
    // read it

    root_dir_sector = clus2sec(fs, 17);

    while (true) {
        errval_t err = fs_read_sector(fs, root_dir_sector, scratch);

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to read root dir sector\n");
            return err;
        }

        char *vbuf = (char *)scratch->virt;
        // print out first block:
        DEBUG_PRINTF("block: %D \n", root_dir_sector++);
        for (int i = 0; i < SDHC_BLOCK_SIZE; i++) {
            if (i % 32 == 0) {
                printf("\n%lx:\t", i);
            }
            printf("%02x", vbuf[i]);
        }
        printf("\n");
        break;
    }

    for (int i = 0; i < 16; i++) {
        struct fat32_dir_entry *curr_dir
            = (struct fat32_dir_entry *)((char *)scratch->virt
                                         + i * sizeof(struct fat32_dir_entry));

        DEBUG_PRINTF("dir entry %d:\n", i);
        DEBUG_PRINTF("fsize: %d\n", curr_dir->FileSize);
        DEBUG_PRINTF("file attributes: %d \n", curr_dir->Attr)
    }
    return SYS_ERR_OK;
}


static errval_t setup_read_buffer(size_t bytes, struct phys_virt_addr *addr)
{
    // TODO is this always an invalid sector?
    addr->last_sector = 0xFFFFFF;

    // get a frame first
    struct capref cap;
    errval_t err = frame_alloc(&cap, bytes, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "frame_alloc");
        return err;
    }

    // map it

    // TODO is this really nocache?
    err = paging_map_frame_attr(get_current_paging_state(), &addr->virt, bytes, cap,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_frame_attr");
        return err;
    }

    if (addr->virt == NULL) {
        DEBUG_PRINTF("virt_base is NULL\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    err = get_phys_addr(cap, (genpaddr_t *)(&addr->phys), NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "get_phys_addr");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t init_fat32(struct fat32 *fs)
{
    // init card
    errval_t err = init_sd(&fs->sd);

    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to init sd\n");
        return err;
    }

    err = setup_read_buffer(BASE_PAGE_SIZE, &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "setup_read_buffer");
        return err;
    }

    err = setup_read_buffer(BASE_PAGE_SIZE, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "setup_read_buffer");
        return err;
    }

    // read first block
    int j = 0;
    err = fs_read_sector(fs, j++, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sdhc_read_block");
        return err;
    }

    char *vbuf = (char *)fs->fat_scratch.virt;
    assert(vbuf[0] == 0xEB);
    assert(vbuf[2] == 0x90);
    assert(vbuf[510] == 0x55);
    assert(vbuf[511] == 0xAA);


    // on FAT32 systems
    uint32_t BPB_RootEntCnt = 0;

    fs->BytesPerSec = *(uint16_t *)(vbuf + FAT32_BPB_BytsPerSec_OFFSET);
    // on FAT32: will always be zero TODO (page 13)
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


    // print out first block:
    /*DEBUG_PRINTF("first block: \n");
    for (int i = 0; i < SDHC_BLOCK_SIZE; i++) {
        if (i % 32 == 0) {
            printf("\n%lx:\t", i);
        }
        printf("%02x", vbuf[i]);
    }
    printf("\n");*/


    return SYS_ERR_OK;
}


static errval_t get_free_cluster(struct fat32 *fs, uint32_t *retcluster)
{
    errval_t err;

    // load FAT table: first sector
    err = fs_read_sector(fs, fs->FirstFatSector, &fs->fat_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sdhc_read_block");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;

    for (int i = 0; i < FAT_ENTRIES_PER_SECTOR(fs); i++) {
        if (fat_entry_is_free(fat[i])) {
            // convert entry index to cluster number
            // debug_printf("index %d is free\n", i);
            *retcluster = fat_index2cluster(fs, fs->FirstFatSector, i);
            return set_fat_entry(fs, *retcluster, FAT_ENTRY_EOF);
        }
    }
    return FS_ERR_NOTFOUND;
}

__attribute__((unused)) static void read_dir(struct fat32 *fs, char *path)
{
    // first: assume path is just "/"
    uint32_t root_dir_sector = clus2sec(fs, fs->FirstRootDirCluster);

    // read root dir
    errval_t err = fs_read_sector(fs, root_dir_sector, &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sdhc_read_block");
        return;
    }
    // print out: attribute + filesize + start cluster
    for (int i = 0; i < 16; i++) {
        struct fat32_dir_entry *curr_dir
            = (struct fat32_dir_entry *)((char *)fs->data_scratch.virt
                                         + i * sizeof(struct fat32_dir_entry));

        DEBUG_PRINTF("dir entry %02d:\tfsize: 0x%08lx\tattr: %02d\tfree: %d\n", i,
                     curr_dir->FileSize, curr_dir->Attr, dir_is_free(curr_dir));
    }
}


/**
 * Assumes data_scratch contains loaded sector with root dir
 *
 */
static errval_t add_dir_entry(struct fat32 *fs, struct fat32_file *file,
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
        err = get_free_cluster(fs, &cluster);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "get_free_cluster");
            return err;
        }
    } else {
        cluster = *start_data_cluster;
    }

    err = fs_read_sector(fs, dir_sector, &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to read dir\n");
    }

    struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt
                                  + dir_index;

    // TODO: check first if name is unique in this directory

    dir->Attr = (uint8_t)file->type;
    dir->FileSize = (file->type != FAT32_FATTR_DIRECTORY) ? file->size : 0;

    dir->FstClusHI = cluster >> 16;
    dir->FstClusLO = cluster & 0xFFFF;

    memcpy(dir->Name, file->name, 11);

    // write file entry to directory!
    err = fs_write_sector(fs, dir_sector, &fs->data_scratch);

    if (allocate_new_start_data_cluster) {
        *start_data_cluster = cluster;
    }

    return err;
}

static errval_t zero_cluster(struct fat32 *fs, uint32_t cluster)
{
    uint32_t curr_sector = clus2sec(fs, cluster);
    memset(fs->data_scratch.virt, 0, fs->BytesPerSec);

    for (uint32_t i = 0; i < fs->SecPerClus; i++) {
        errval_t err = fs_write_sector(fs, curr_sector + i, &fs->data_scratch);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write sector");
            return err;
        }
    }
    return SYS_ERR_OK;
}


static errval_t allocate_and_link_cluster(struct fat32 *fs, uint32_t curr_cluster,
                                          uint32_t *new_cluster)
{
    // get a free cluster
    errval_t err = get_free_cluster(fs, new_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get free cluster");
        return err;
    }

    // link it to the current cluster
    // read fat table entry for the current cluster we're writing
    err = set_fat_entry(fs, curr_cluster, *new_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set fat entry");
        return err;
    }

    err = set_fat_entry(fs, *new_cluster, FAT_ENTRY_EOF);
     if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set fat entry of new cluster");
        return err;
    }
    return SYS_ERR_OK;
}

static inline uint32_t next_data_cluster(struct fat32 *fs, uint32_t curr_cluster)
{
    uint32_t entry = get_fat_entry(fs, curr_cluster);
    return entry;
}


static errval_t file_exists_in_curr_dir(struct fat32 *fs, uint32_t dir_cluster,
                                        char *fName, bool *res)
{
    while (!fat_entry_is_eof(dir_cluster)) {
        uint32_t start_sector = clus2sec(fs, dir_cluster);

        for (uint32_t sector = start_sector; sector < start_sector + fs->SecPerClus;
             sector++) {
            errval_t err = fs_read_sector(fs, sector, &fs->data_scratch);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to read sector\n");
                return err;
            }

            struct fat32_dir_entry *dir_entry
                = (struct fat32_dir_entry *)(fs->data_scratch.virt);

            for (int i = 0; i < DIR_ENTRIES_PER_SECTOR(fs); i++) {
                if (memcmp(fName, dir_entry[i].Name, 11) == 0) {
                    *res = true;
                    return SYS_ERR_OK;
                }
            }
        }
        dir_cluster = next_data_cluster(fs, dir_cluster);
    }

    *res = false;

    return SYS_ERR_OK;
}

static errval_t add_file_to_dir(struct fat32 *fs, uint32_t dir_cluster,
                                struct fat32_file *file, uint32_t *ret_start_data_cluster)
{
    // find free spot in dir
    // read dir
    if (fat_entry_is_eof(dir_cluster) || fat_entry_is_bad_cluster(dir_cluster)) {
        DEBUG_PRINTF("invalid cluster in add_to_dir\n");
        // TODO: invalid cluster error
        return FS_ERR_NOTFOUND;
    }

    errval_t err;

    bool fexists;
    err = file_exists_in_curr_dir(fs, dir_cluster, file->name, &fexists);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't check if file exists in dir\n");
        return err;
    }

    if (fexists) {
        DEBUG_PRINTF("file already exists\n");
        return FS_ERR_EXISTS;
    }

    uint32_t dir_sector = clus2sec(fs, dir_cluster);

    int i;
    while (!fat_entry_is_eof(dir_cluster)) {
        uint32_t start_sector = clus2sec(fs, dir_cluster);
        for (dir_sector = start_sector; dir_sector < start_sector + fs->SecPerClus;
             dir_sector++) {
            err = fs_read_sector(fs, dir_sector, &fs->data_scratch);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to read sector while adding file to dir\n");
                return err;
            }

            struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt;

            for (i = 0; i < 16; i++) {
                if (dir_is_free(&dir[i])) {
                    // found free spot
                    debug_printf("dir index %d is free\n", i);
                    goto found;
                }
            }
        }
        dir_cluster = next_data_cluster(fs, dir_cluster);
    }

    DEBUG_PRINTF("no more room in directory, allocating a new cluster!\n");

    // add a new cluster
    err = allocate_and_link_cluster(fs, dir_cluster, &dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't link a new data cluster to full dir cluster\n");
        return err;
    }

    err = zero_cluster(fs, dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't zero out the new dir cluster\n");
        return err;
    }

    // new cluster, use first entry
    i = 0;

found:
    err = add_dir_entry(fs, file, dir_sector, i, ret_start_data_cluster, true);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't add a new directory entry in add_file_to_dir\n");
    }

    return err;
}

/**
 * @brief Get the path dir prefix object
 *
 * @param path path
 * @return uint32_t index of last '/' in path, or -1 if no '/' found
 */
int get_path_dir_prefix(const char *name)
{
    size_t N = strlen(name);

    for (int i = N - 1; i > 0; i--) {
        if (name[i] == '/') {
            return i;
        }
    }
    return -1;
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
errval_t load_dir_entry_from_name(struct fat32 *fs, uint32_t containing_dir_cluster,
                                  char *name, struct fat32_dir_entry *ret_dir,
                                  uint32_t *ret_sector, uint32_t *ret_index)
{
    // check if file of that name exists in any of the directory entries
    DEBUG_PRINTF("FAT32: looking for dir entry: \"%.11s\"\n", name);

    while (!fat_entry_is_eof(containing_dir_cluster)) {
        uint32_t start_sector = clus2sec(fs, containing_dir_cluster);
        for (int sector = start_sector; sector < start_sector + fs->SecPerClus; sector++) {
            // load sector
            errval_t err = fs_read_sector(fs, clus2sec(fs, containing_dir_cluster),
                                          &fs->data_scratch);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to read directory sector \n");
                return err;
            }

            struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt;
            for (int i = 0; i < DIR_ENTRIES_PER_SECTOR(fs); i++) {
                /*char nn[12];
                    memcpy(nn, dir[i].Name, 11);
                    nn[11] = 0;
                    debug_printf("entry name: \"%s\"\n", nn);
                */
                if (memcmp(name, dir[i].Name, 11) == 0) {
                    // found file
                    memcpy(ret_dir, &dir[i], sizeof(struct fat32_dir_entry));
                    if (ret_sector != NULL) {
                        *ret_sector = sector;
                    }
                    if (ret_index != NULL) {
                        *ret_index = i;
                    }
                    return SYS_ERR_OK;
                }
            }
        }
        containing_dir_cluster = next_data_cluster(fs, containing_dir_cluster);
    }

    DEBUG_PRINTF("couldn't find entry with matching name in directory\n");
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
errval_t move_to_dir(struct fat32 *fs, char *full_path, uint32_t *retcluster)
{
    errval_t err = SYS_ERR_OK;

    uint32_t curr_cluster = fs->FirstRootDirCluster;

    char dir_arr[12];
    char *curr_path_dir = (char *)dir_arr;

    struct path_list_node *path_list = get_path_list(full_path);
    struct path_list_node *curr = path_list;

    while (curr) {
        bool valid = to_fat32_short_name(curr->dir, curr_path_dir);
        if (!valid) {
            DEBUG_PRINTF("invalid name in path\n");
            err = FS_ERR_NOTFOUND;
            goto unwind;
        }

        char *next_file_in_dir = curr_path_dir;
        struct fat32_dir_entry dir_entry;
        err = load_dir_entry_from_name(fs, curr_cluster, next_file_in_dir, &dir_entry,
                                       NULL, NULL);
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
    uint32_t start_sector = clus2sec(fs, cluster);

    assert(offset + bytes <= fs->SecPerClus * fs->BytesPerSec);
    uint32_t curr_sector = start_sector + offset / fs->BytesPerSec;

    offset %= fs->BytesPerSec;

    while (bytes > 0) {
        err = fs_read_sector(fs, curr_sector, &fs->data_scratch);
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
            err = fs_write_sector(fs, curr_sector, &fs->data_scratch);
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
    uint32_t bytes_per_clus = fs->BytesPerSec * fs->SecPerClus;

    while (curr_offset >= bytes_per_clus) {
        curr_offset -= bytes_per_clus;
        curr_cluster = next_data_cluster(fs, curr_cluster);
        if (fat_entry_is_eof(curr_cluster)) {
            DEBUG_PRINTF("offset is undefined!\n");
            return FS_ERR_NOTFOUND;
        }
    }

    *ret_cluster = curr_cluster;
    return SYS_ERR_OK;
}

errval_t fat32_write_data(struct fat32 *fs, uint32_t start_cluster,
                          uint32_t cluster_offset, char *src_buffer,
                          uint32_t bytes, uint32_t *ret_last_cluster_written)
{
    errval_t err = SYS_ERR_OK;

    uint32_t prev_cluster, curr_cluster;
    uint32_t bytes_read = 0;

    curr_cluster = prev_cluster = start_cluster;

    while (bytes_read < bytes) {
        uint32_t bytes_to_read = MIN(bytes - bytes_read,
                                     fs->BytesPerSec * fs->SecPerClus - cluster_offset);
        err = fat32_process_cluster(fs, curr_cluster, cluster_offset, src_buffer,
                                    bytes_to_read, false);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write cluster\n");
            return err;
        }

        if(bytes_to_read == fs->BytesPerSec * fs->SecPerClus - cluster_offset) {
            // cluster is full; set new one
            prev_cluster = curr_cluster;
            curr_cluster = next_data_cluster(fs, prev_cluster);
            DEBUG_PRINTF("going to next data cluster\n");
    
            if (fat_entry_is_eof(curr_cluster)) {
                DEBUG_PRINTF("new cluster allocated and linked\n");
                err = allocate_and_link_cluster(fs, prev_cluster, &curr_cluster);
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

    /*
    // delete any clusters after than and set EOF here
    err = set_cluster_eof(fs, curr_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to delete clusters after\n");
        return err;
    }
    */

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
                                     fs->BytesPerSec * fs->SecPerClus - cluster_offset);
        err = fat32_process_cluster(fs, curr_cluster, cluster_offset, dest_buffer,
                                    bytes_to_read, true);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to read cluster\n");
            return err;
        }
        if (bytes_to_read  ==  fs->BytesPerSec * fs->SecPerClus - cluster_offset) {
            // cluster is full; move to next one
            curr_cluster = next_data_cluster(fs, curr_cluster);
            DEBUG_PRINTF("reading from next data cluster: %d\n", curr_cluster);
        }

        bytes_read += bytes_to_read;
        dest_buffer += bytes_to_read;
        cluster_offset = 0;

    }

    *ret_last_cluster_read = curr_cluster;

    return SYS_ERR_OK;
}


errval_t read_file(struct fat32 *fs, char *path, char *file)
{
    errval_t err;

    uint32_t containing_dir_cluster = 0;

    char new_name[12];
    new_name[11] = 0;
    bool res = to_fat32_short_name(file, new_name);
    if (!res) {
        DEBUG_PRINTF("invalid file name!\n");
        return FS_ERR_NOTFILE;
    }
    file = new_name;

    err = move_to_dir(fs, path, &containing_dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "move_to_dir failed");
        return err;
    }

    // get file info
    struct fat32_dir_entry dir;
    err = load_dir_entry_from_name(fs, containing_dir_cluster, file, &dir, NULL, NULL);

    uint32_t file_data_cluster = dir.FstClusHI << 16 | dir.FstClusLO;
    // read file!
    print_file(fs, file_data_cluster, dir.FileSize);

    return SYS_ERR_OK;
}

errval_t write_cluster(struct fat32 *fs, uint32_t cluster, char *payload, size_t size)
{
    assert(size <= fs->BytesPerSec * fs->SecPerClus);

    errval_t err;

    uint32_t curr_sector = clus2sec(fs, cluster);
    uint32_t remaining_size = size;

    while (remaining_size) {
        // write this sector
        uint32_t bytes = MIN(remaining_size, fs->BytesPerSec);
        memcpy(fs->data_scratch.virt, payload, bytes);

        // write sector
        err = fs_write_sector(fs, curr_sector, &fs->data_scratch);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to write sector");
            return err;
        }

        payload += bytes;
        remaining_size -= bytes;
        curr_sector++;
    }
    return SYS_ERR_OK;
}

static errval_t write_file_data(struct fat32 *fs, uint32_t start_data_cluster,
                                struct fat32_file *file)
{
    uint32_t written = 0;

    uint32_t curr_cluster = start_data_cluster;

    while (written < file->size) {
        // load sector
        uint32_t bytes = MIN(file->size - written, fs->BytesPerSec * fs->SecPerClus);
        write_cluster(fs, curr_cluster, file->payload + written, bytes);

        written += bytes;

        // allocate a new data cluster if needed

        if (written < file->size) {
            allocate_and_link_cluster(fs, curr_cluster, &curr_cluster);
        }
    }
    // set EOF cluster into FAT
    errval_t err = set_fat_entry(fs, curr_cluster, FAT_ENTRY_EOF);

    return err;
}

static errval_t initialize_dir(struct fat32 *fs, uint32_t containing_dir_cluster,
                               uint32_t new_dir_cluster, struct fat32_file *file)
{
    errval_t err;

    debug_printf("initializing in cluster %d\n", new_dir_cluster);

    uint32_t new_dir_sector = clus2sec(fs, new_dir_cluster);

    err = zero_cluster(fs, new_dir_cluster);
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

    err = add_dir_entry(fs, &dot, new_dir_sector, 0, &new_dir_cluster, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to add dot entry to new dir\n");
        return err;
    }
    err = add_dir_entry(fs, &dotdot, new_dir_sector, 1, &containing_dir_cluster, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to add dotdot entry to new dir\n");
        return err;
    }

    // create directory entry for "."
    // create directory entry for ".."


    return SYS_ERR_OK;
}

errval_t write_file(struct fat32 *fs, char *dest_dir, struct fat32_file file)
{
    errval_t err;
    uint32_t containing_dir_cluster;

    char new_name[12];
    new_name[11] = 0;
    bool res = to_fat32_short_name(file.name, new_name);
    if (!res) {
        DEBUG_PRINTF("invalid file name!\n");
        return FS_ERR_NOTFILE;
    }
    file.name = new_name;

    err = move_to_dir(fs, dest_dir, &containing_dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "move_to_dir failed");
        return err;
    }

    debug_printf("moved in tree: \"%s\", now writing file: \"%s\"\n", dest_dir, file.name);
    debug_printf("start cluster: %d, curr cluster: %d\n", fs->FirstRootDirCluster,
                 containing_dir_cluster);

    //  write file entry into directory
    uint32_t start_data_cluster;
    err = add_file_to_dir(fs, containing_dir_cluster, &file, &start_data_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "couldn't write file entry to dir\n");
        return err;
    }

    debug_printf("added file entry to dir: first data cluster: %d\n", start_data_cluster);

    // write the actual file into the data clusters
    if (file.type == FAT32_FATTR_DIRECTORY) {
        debug_printf("initializing dir\n");
        err = initialize_dir(fs, containing_dir_cluster, start_data_cluster, &file);
    } else {
        debug_printf("initializing file\n");
        err = write_file_data(fs, start_data_cluster, &file);
    }
    return SYS_ERR_OK;
}

__attribute__((unused)) static void test_short_name(char *old)
{
    char new_name[12];
    bool valid = to_fat32_short_name(old, new_name);
    new_name[11] = '\0';

    debug_printf("old: \"%s\" -> new name: \"%s\"\n", old, valid ? new_name : "INVALID");
}

errval_t set_cluster_eof(struct fat32 *fs, uint32_t curr_cluster)
{
    errval_t err;
    uint32_t next_cluster = get_fat_entry(fs, curr_cluster);

    if(fat_entry_is_eof(next_cluster)) {
        return SYS_ERR_OK;
    }

    err = set_fat_entry(fs, curr_cluster, FAT_ENTRY_EOF);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to set EOF entry in FAT\n");
        return err;
    }

    curr_cluster = get_fat_entry(fs, next_cluster);
    while (!fat_entry_is_free(curr_cluster)) {
        next_cluster = get_fat_entry(fs, curr_cluster);
        err = set_fat_entry(fs, curr_cluster, FAT_ENTRY_FREE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to set free entry in FAT\n");
            return err;
        }
        curr_cluster = next_cluster;
        if(fat_entry_is_eof(curr_cluster)){
            break;
        }
    }

    return SYS_ERR_OK;
}


errval_t fat32_set_fdata(struct fat32 *fs, uint32_t dir_sector, uint32_t dir_index,
                         uint32_t start_data_cluster, uint32_t size)
{
    errval_t err;

    err = fs_read_sector(fs, dir_sector, &fs->data_scratch);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Couldn't read dir-entry sector\n");
        return err;
    }

    struct fat32_dir_entry *dir_entry = (struct fat32_dir_entry *)fs->data_scratch.virt + dir_index; 
    
    dir_entry->FileSize = size;
    dir_entry->FstClusHI = start_data_cluster >> 16;
    dir_entry->FstClusLO = start_data_cluster & 0xFFFF;

    err = fs_write_sector(fs, dir_sector, &fs->data_scratch);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to write back updated dir-entry!\n");
        return err;
    }

    return SYS_ERR_OK;

}



errval_t fat32_create_empty_file(struct fat32 *fs, char *path){

    errval_t err;

    char *prefix, *fname;
    split_path(path, &prefix, &fname);

    uint32_t parent_dir_cluster;
    err = move_to_dir(fs, prefix, &parent_dir_cluster);

    char fat32_short_name[11];
    bool valid = to_fat32_short_name(fname, fat32_short_name);
    if(!valid){
        DEBUG_PRINTF("Couldn't convert filename to short name: %s\n", fname);
        return err;
    }
    struct fat32_file file = {
        .name = fat32_short_name, .size = 0, .payload = NULL, .type = 0
    };   

    uint32_t start_data_cluster; 
    err = add_file_to_dir(fs, parent_dir_cluster, &file, &start_data_cluster);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "Failed to write new file entry to dir\n");
    }


    return SYS_ERR_OK;
}

void split_path(const char *full_path, char **path_prefix, char **fname)
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