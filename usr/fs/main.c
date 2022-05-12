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

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/deferred.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/cache.h>


#define FAT32_BPB_BytsPerSec_OFFSET 11
#define FAT32_BPB_SecPerClus_OFFSET 13
#define FAT32_BPB_RsvdSecCnt_OFFSET 14
#define FAT32_BPB_NumFATs_OFFSET 16
#define FAT32_BPB_TotSec32_OFFSET 32
#define FAT32_BPB_FATSz32_OFFSET 36
#define FAT32_BPB_RootClus_OFFSET 44
#define FAT32_BPB_FSInfo_OFFSET 48

void *sd_mem_base;

static inline lpaddr_t shdc_get_phys_addr(void *addr)
{
    size_t offset = (size_t)addr - (size_t)sd_mem_base;

    size_t phys_base = IMX8X_SDHC2_BASE;
    return (lpaddr_t)(phys_base + offset);
}

struct phys_virt_addr {
    lpaddr_t phys;
    void *virt;
};


struct fat32_file {
    char *name;
    char *payload;
    uint32_t size;
    bool read_only;
};


struct fat32 {
    struct sdhc_s *sd;
    uint16_t BytesPerSec;
    uint32_t RootDirSectors;
    uint8_t SecPerClus;
    uint32_t FatSz;
    uint8_t NumFATs;
    uint32_t TotSec;
    uint32_t DataSec;
    uint16_t RsvdSecCnt;
    uint32_t FirstDataSector;

    uint32_t CountOfClusters;
    uint32_t FirstRootDirCluster;
    uint32_t FirstFatSector;

    struct phys_virt_addr data_scratch;
    struct phys_virt_addr fat_scratch;
};


enum fat32_file_attribute {
    FAT32_FATTR_READ_ONLY = 0x01,
    FAT32_FATTR_HIDDEN = 0x02,
    FAT32_FATTR_SYSTEM = 0x04,
    FAT32_FATTR_VOLUME_ID = 0x08,
    FAT32_FATTR_DIRECTORY = 0x10,
    FAT32_FATTR_ARCHIVE = 0x20,
    FAT32_FATTR_LONG_NAME = FAT32_FATTR_READ_ONLY | FAT32_FATTR_HIDDEN
                            | FAT32_FATTR_SYSTEM | FAT32_FATTR_VOLUME_ID
};

struct fat32_dir_entry {
    // Offset: 0, Size: 11
    uint8_t Name[11];
    // Offset: 11, Size: 1
    uint8_t Attr;
    // Offset: 12, Size: 1
    uint8_t NTRes;
    // Offset: 13, Size: 1
    uint8_t CrtTimeTenth;
    // Fill buf to offset 20
    uint8_t Unused[6];
    // Offset: 20, Size: 2
    uint16_t FstClusHI;
    // Offset: 22, Size: 2
    uint16_t WrtTime;
    // Offset: 24, Size: 2
    uint16_t WrtDate;
    // Offset: 26, Size: 2
    uint16_t FstClusLO;
    // Offset: 28, Size: 4
    uint32_t FileSize;
};


struct fat32_long_dir_entry {
    uint8_t Ord;
    uint8_t Name1[10];
    uint8_t Attr;
    uint8_t Type;
    uint8_t Checksum;
    uint8_t Name2[12];
    // MBZ
    uint16_t FstClusHI;
    uint8_t Name3[4];
};


#define FAT_ENTRIES_PER_SECTOR(fs) ((fs)->BytesPerSec / 4)
#define DIR_ENTRIES_PER_SECTOR(fs) ((fs)->BytesPerSec / 32)

#define FAT_ENTRY_EOF 0x0FFFFFFF

__attribute__((unused)) static inline bool fat_entry_is_eof(uint32_t fat_entry)
{
    return fat_entry > 0x0FFFFFF8;
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

__attribute__((unused)) static errval_t fs_read_sector(struct fat32 *fs, uint32_t sector,
                                                       struct phys_virt_addr *addr)
{
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    return sdhc_read_block(fs->sd, sector, addr->phys);
}

__attribute__((unused)) static errval_t fs_write_sector(struct fat32 *fs, uint32_t sector,
                                                        struct phys_virt_addr *addr)
{
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    errval_t res = sdhc_write_block(fs->sd, sector, addr->phys);
    // TODO both cache flushes aren't necessary
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    return res;
}

__attribute__((unused)) static inline uint32_t clus2sec(struct fat32 *fs, uint32_t cluster)
{
    return fs->FirstDataSector + (cluster - 2) * fs->SecPerClus;
}


__attribute__((unused)) static inline void cluster2fat_index(struct fat32 *fs,
                                                             uint32_t cluster,
                                                             uint32_t *fat_sector,
                                                             uint32_t *fat_index)
{
    uint32_t fat_offset = cluster * 4;
    *fat_sector = fs->RsvdSecCnt + (fat_offset / fs->BytesPerSec);
    // uint32_t entries_per_sector = fs->BytesPerSec / 4;
    *fat_index = (fat_offset % fs->BytesPerSec) / 4;
    DEBUG_PRINTF("fat_sector: %d, fat_index: %d\n", *fat_sector, *fat_index);
}


__attribute__((unused)) static inline uint32_t
fat_index2cluster(struct fat32 *fs, uint32_t fat_sector, uint32_t fat_index)
{
    return fat_index + (fat_sector - fs->FirstFatSector) * FAT_ENTRIES_PER_SECTOR(fs);
}

__attribute__((unused)) static inline uint32_t get_fat_entry(struct fat32 *fs,
                                                             uint32_t cluster)
{
    uint32_t fat_sector, fat_index;
    cluster2fat_index(fs, cluster, &fat_sector, &fat_index);

    printf("look for index: %d\n", fat_index);
    // Read FAT sector
    fs_read_sector(fs->sd, fat_sector, &fs->fat_scratch);

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;
    for (int i = 0; i < 128; i++) {
        printf("%d: %lx\n", i, fat[i] & 0x0FFFFFFF);
    }

    return 0;
}


static errval_t set_fat_entry(struct fat32 *fs, uint32_t curr_cluster, uint32_t new_cluster){
    uint32_t fat_sector, fat_index;
    cluster2fat_index(fs, curr_cluster, &fat_sector, &fat_index);
    errval_t err = fs_read_sector(fs->sd, fat_sector, &fs->fat_scratch);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed to read FAT sector");
        return err;
    }

    uint32_t *fat = (uint32_t *)fs->fat_scratch.virt;
    // TODO top bits need to be kept
    fat[fat_index] = new_cluster;
    return fs_write_sector(fs->sd, fat_sector, &fs->fat_scratch);

}

__attribute__((unused)) static inline void print_file(struct fat32 *fs, uint32_t cluster,
                                                      uint32_t size)
{
    while (size) {
        uint32_t fat_sector, fat_index;
        cluster2fat_index(fs, cluster, &fat_sector, &fat_index);

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

static errval_t init_sd(struct sdhc_s **sd)
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
static errval_t read_root_dir(struct fat32 *fs, struct phys_virt_addr *scratch)
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

static errval_t init_fat32(struct fat32 *fs)
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

__attribute__((unused)) static errval_t get_free_cluster(struct fat32 *fs,
                                                         uint32_t *retcluster)
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
        debug_printf("%d: %d\n", i, fat[i]);
    }

    for (int i = 0; i < FAT_ENTRIES_PER_SECTOR(fs); i++) {
        if (fat_entry_is_free(fat[i])) {
            // convert entry index to cluster number
            debug_printf("index %d is free\n", i);
            *retcluster = fat_index2cluster(fs, fs->FirstFatSector, i);
            return SYS_ERR_OK;
        }
    }
    return FS_ERR_NOTFOUND;
}

static void read_dir(struct fat32 *fs, char *path)
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
__attribute__((unused)) static errval_t add_dir_entry(struct fat32 *fs,
                                                      struct fat32_file *file,
                                                      uint32_t dir_sector,
                                                      uint32_t dir_index,
                                                      uint32_t *ret_start_data_cluster)
{
    // assumes sector is already loaded
    assert(dir_index < DIR_ENTRIES_PER_SECTOR(fs));
    // get a free cluster for content
    uint32_t cluster;
    errval_t err = get_free_cluster(fs, &cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "get_free_cluster");
        return err;
    }

    struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt
                                  + dir_index;

    // TODO: check first if name is unique in this directory

    dir->Attr = (uint8_t)file->read_only;
    dir->FileSize = file->size;

    dir->FstClusHI = cluster >> 16;
    dir->FstClusLO = cluster & 0xFFFF;

    memcpy(dir->Name, file->name, 11);

    // write file entry to directory!
    err = fs_write_sector(fs, dir_sector, &fs->data_scratch);

    *ret_start_data_cluster = cluster;

    return err;
}


__attribute__((unused)) static errval_t
add_file_to_dir(struct fat32 *fs, uint32_t dir_cluster, struct fat32_file *file, uint32_t *ret_start_data_cluster)
{
    // find free spot in dir
    // read dir
    uint32_t dir_sector = clus2sec(fs, dir_cluster);
    fs_read_sector(fs, dir_sector, &fs->data_scratch);

    struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt;

    bool found = false;
    int i;
    for (i = 0; i < 16; i++) {
        if (dir_is_free(&dir[i])) {
            // found free spot
            debug_printf("dir index %d is free\n", i);
            found = true;
            break;
        }
    }

    if (!found) {
        return FS_ERR_NOTFOUND;
    }

    errval_t err = add_dir_entry(fs, file, dir_sector, i, ret_start_data_cluster);

    return err;
}

/**
 * @brief Get the path dir prefix object
 *
 * @param path path
 * @return uint32_t index of last '/' in path, or -1 if no '/' found
 */
__attribute__((unused)) static int get_path_dir_prefix(char *name)
{
    int i;
    size_t N = strlen(name);

    for (int i = N - 1; i > 0; i--) {
        if (name[i] == '/') {
            return i;
        }
    }
    return -1;
}

static int get_next_dir_in_path(char *name)
{
    for (int i = 0; name[i] != '\0'; i++) {
        if (name[i] == '/') {
            return i;
        }
    }
    return -1;
}

/**
 * @brief Loads the directory entry of a file in the given directory cluster
 *
 * @param fs FAT32 filesystem
 * @param containing_dir_cluster Cluster to start of containing directory
 * @param name Name fo the entry to load
 * @param ret_dir Copy of the directory entry
 * @return errval_t Success if file exists, else error
 */
static errval_t load_dir_entry_from_name(struct fat32 *fs, uint32_t containing_dir_cluster,
                                         char *name, struct fat32_dir_entry *ret_dir)
{
    // check if file of that name exists in any of the directory entries

    // load sector
    errval_t err = fs_read_sector(fs, clus2sec(fs, containing_dir_cluster),
                                  &fs->data_scratch);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to read directory sector \n");
        return err;
    }

    struct fat32_dir_entry *dir = (struct fat32_dir_entry *)fs->data_scratch.virt;
    for (int i = 0; i < DIR_ENTRIES_PER_SECTOR(fs); i++) {
        if (memcmp(name, dir[i].Name, 11) == 0) {
            // found file
            memcpy(ret_dir, &dir[i], sizeof(struct fat32_dir_entry));
            return SYS_ERR_OK;
        }
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
static errval_t move_to_dir(struct fat32 *fs, char *dir, uint32_t *retcluster)
{
    uint32_t curr_cluster = clus2sec(fs, fs->FirstRootDirCluster);

    while (*dir != '\0') {
        int next_index = get_next_dir_in_path(dir);
        if (next_index == -1) {
            DEBUG_PRINTF("couldn't move to dir: %s\n", dir);
            return FS_ERR_NOTFOUND;
        }

        char old_char = dir[next_index];

        // we'll make this a single string to separate it from the rest of the path
        dir[next_index] = '\0';
        // new name to avoid confusion
        char *next_file_in_dir = dir;

        struct fat32_dir_entry dir_entry;
        errval_t err = load_file(fs, curr_cluster, next_file_in_dir, &dir_entry);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "load_dir failed");
            return err;
        }

        // revert again to include postfix of path
        dir[next_index] = old_char;
        // skip to the next dir in path
        dir += next_index + 1;
    }

    *retcluster = curr_cluster;

    return SYS_ERR_OK;
}

static errval_t read_file(struct fat32 *fs, char *path)
{
    errval_t err;

    uint32_t containing_dir_cluster;

    // separate last file in path from it
    int last_index = get_path_dir_prefix(path);
    char old_char = path[last_index];
    path[last_index] = '\0';

    err = move_to_dir(fs, path, &containing_dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "move_to_dir failed");
        return err;
    }

    path[last_index] = old_char;

    char *file = path + last_index + 1;
    // load file

    // get file info
    struct fat32_dir_entry dir;
    err = load_dir_entry_from_name(fs, containing_dir_cluster, file, &dir);

    uint32_t file_data_cluster = dir.FstClusHI << 16 | dir.FstClusLO;
    // read file!
    print_file(fs, file_data_cluster, dir.FileSize);

    return SYS_ERR_OK;
}

static errval_t write_file_entry_to_dir(struct fat32 *fs, uint32_t containing_dir_cluster,
                                        struct fat32_file *file,
                                        uint32_t *start_data_cluster)
{
    errval_t err;

    // load directory
    err = fs_read_sector(fs, clus2sec(fs, containing_dir_cluster), &fs->data_scratch);
    // get a free entry in the directory
    int free_index = get_free_dir_index(fs, containing_dir_cluster);
}

static errval_t write_cluster(struct fat32 *fs, uint32_t cluster, char *payload, size_t size)
{
    assert(size <= fs->BytesPerSec * fs->SecPerClus);

    errval_t err;

    uint32_t curr_sector = clus2sec(fs, cluster);
    uint32_t remaining_size = size;

    while(remaining_size){
        // write this sector
        uint32_t bytes = MIN(remaining_size, fs->BytesPerSec);
        memcpy(fs->data_scratch.virt, payload, bytes);

        // write sector
        err = fs_write_sector(fs, curr_sector, &fs->data_scratch);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "failed to write sector");
            return err;
        }
    
        payload += bytes;
        remaining_size -= bytes;
        curr_sector++;
    }
    return SYS_ERR_OK;
}

static errval_t allocate_and_link_cluster(struct fat32 *fs, uint32_t curr_cluster, uint32_t *new_cluster)
{
    // get a free cluster
    errval_t err = get_free_cluster(fs, new_cluster);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed to get free cluster");
        return err;
    }

    // link it to the current cluster
    // read fat table entry for the current cluster we're writing
    err = set_fat_entry(fs, curr_cluster, *new_cluster);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "failed to set fat entry");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t write_file_data(struct fat32 *fs, uint32_t start_data_cluster, struct fat32_file *file){
    uint32_t written = 0;

    uint32_t curr_cluster = start_data_cluster;
    uint32_t curr_sector = clus2sec(fs, curr_cluster);

    while(written < file->size){
        // load sector
        uint32_t bytes = MIN(file->size - written, fs->BytesPerSec * fs->SecPerClus);
        write_cluster(fs, curr_cluster, file->payload + written, bytes);

        written += bytes; 

        // allocate a new data cluster if needed

        if(written < file->size){
            allocate_and_link_cluster(fs, curr_cluster, &curr_cluster);
        }
    }
    // set EOF cluster into FAT
    errval_t err = set_fat_entry(fs, curr_cluster, FAT_ENTRY_EOF);

    return SYS_ERR_OK;
}

static errval_t write_file(struct fat32 *fs, char *dest_dir, struct fat32_file file)
{
    errval_t err;

    uint32_t containing_dir_cluster;

    err = move_to_dir(fs, dest_dir, &containing_dir_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "move_to_dir failed");
        return err;
    }

    //  write file entry into directory
    uint32_t start_data_cluster;
    errval_t err = add_file_to_dir(fs, containing_dir_cluster, &file,
                                           &start_data_cluster);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "couldn't write file entry to dir\n");
        return err;
    }

    // write the actual file into the data clusters
    err = write_file_data(fs, start_data_cluster, &file);

    return SYS_ERR_OK;
}


/*
read_file: fName:
    path, fName = split1(path)

    dir_cluster = moveToDir(path)

    read_file(curr_dir, file)


add_file path:
    path, fName = split1(path)

    dir_cluster = moveToDir(path)

    // we're in file name now!
    // add file to dir:
    write_file(curr_dir, file)

moveToDir: fName:
    split = split fname

    curr_dir = root_dir_cluster

    curr = split;
    while(curr->next){
        // go to next dir
        curr_dir = get_dir_cluster(curr_dir, curr->name);
        curr = curr->next;
    }
    return curr_dir




write_file file:
    first_cluster = get_free_cluster()
    add_file_to_dir(curr_dir, first_cluster, file)
    write_file(first_cluster, file.data)
*/


int main(int argc, char *argv[])
{
    struct fat32 fs;

    errval_t err = init_fat32(&fs);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "init_fat32");
        return 1;
    }


    add_file_to_dir(&fs, fs.FirstRootDirCluster, "test.txt");
    // read root dir
    read_dir(&fs, "/");


    return 0;
    uint32_t cluster_index = 0;
    err = get_free_cluster(&fs, &cluster_index);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "get_free_cluster");
        return 1;
    }

    debug_printf("free cluster at: %d\n", cluster_index);

    read_dir(&fs, "/");

    print_file(&fs, 17, 512 * 9);
    return 0;

    err = read_root_dir(&fs, &(fs.data_scratch));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "print_root_dir");
        return 1;
    }


    return 0;
    get_fat_entry(&fs, 17);
    return EXIT_SUCCESS;
}

/**
 *
 * @brief Tomorrow: Add minimal support for long dirs
 * - Add support for browsing
 * - Add support for reading files given a path
 * - Add support for writing a file
 * - Add support for writing a directory
 *
 */