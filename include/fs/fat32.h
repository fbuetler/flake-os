#ifndef __fs_FAT32_H__
#define __fs_FAT32_H__


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
#include <fs/sd.h>


#define FAT32_BPB_BytsPerSec_OFFSET 11
#define FAT32_BPB_SecPerClus_OFFSET 13
#define FAT32_BPB_RsvdSecCnt_OFFSET 14
#define FAT32_BPB_NumFATs_OFFSET 16
#define FAT32_BPB_TotSec32_OFFSET 32
#define FAT32_BPB_FATSz32_OFFSET 36
#define FAT32_BPB_RootClus_OFFSET 44
#define FAT32_BPB_FSInfo_OFFSET 48

#define FAT_ENTRIES_PER_SECTOR(fs) ((fs)->BytesPerSec / 4)
#define DIR_ENTRIES_PER_SECTOR(fs) ((fs)->BytesPerSec / 32)
#define DIR_ENTRIES_PER_CLUSTER(fs) (DIR_ENTRIES_PER_SECTOR((fs)) * fs->SecPerClus)

#define FAT_ENTRY_EOF 0x0FFFFFFF
#define FAT_ENTRY_FREE 0x00000000

// first index of file name determines status
#define FAT32_FNAME_FREE '\0'

#define BYTES_PER_CLUS(fs) ((fs)->BytesPerSec * (fs)->SecPerClus)
#define FAT32_DIR_SIZE(fs) ((fs)->BytesPerSec / sizeof(struct fat32_dir_entry))


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


struct fat32_file {
    char *name;
    char *payload;
    uint32_t size;
    enum fat32_file_attribute type;
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

errval_t init_fat32(struct fat32 *fs);

errval_t fat32_read_sector(struct fat32 *fs, uint32_t sector, struct phys_virt_addr *addr);

errval_t fat32_write_sector(struct fat32 *fs, uint32_t sector, struct phys_virt_addr *addr);

errval_t fat32_move_to_dir(struct fat32 *fs, char *full_path, uint32_t *retcluster);

errval_t fat32_process_cluster(struct fat32 *fs, uint32_t cluster, uint32_t offset,
                               char *dest_buffer, uint32_t bytes, bool is_read);

errval_t fat32_read_data(struct fat32 *fs, uint32_t start_cluster,
                         uint32_t cluster_offset, char *dest_buffer, uint32_t bytes,
                         uint32_t *ret_last_cluster_read);

errval_t fat32_get_cluster_from_offset(struct fat32 *fs, uint32_t start_cluster,
                                       off_t offset, uint32_t *ret_cluster);

errval_t fat32_write_data(struct fat32 *fs, uint32_t start_cluster,
                          uint32_t cluster_offset, char *src_buffer, uint32_t bytes,
                          uint32_t *ret_last_cluster_written);

errval_t fat32_load_dir_entry_from_name(struct fat32 *fs, uint32_t containing_dir_cluster,
                                  char *name, struct fat32_dir_entry *ret_dir,
                                  uint32_t *ret_cluster, uint32_t *ret_index);

bool fat32_encode_fname(char *old, char *new_name);
void fat32_decode_fname(char *encoded, char *decoded);

errval_t fat32_set_cluster_eof(struct fat32 *fs, uint32_t curr_cluster);

errval_t fat32_create_empty_file(struct fat32 *fs, const char *path, bool is_dir);

errval_t free_cluster_chain(struct fat32 *fs, uint32_t start_data_cluster);

errval_t fat32_delete_file(struct fat32 *fs, uint32_t dir_cluster, uint32_t index);

errval_t fat32_load_next_dir_entry(struct fat32 *fs, uint32_t first_dir_data_cluster,
                             uint32_t start_index, struct fat32_dir_entry *ret_dir,
                             uint32_t *ret_cluster, uint32_t *ret_index);

bool fat32_is_dir_empty(struct fat32 *fs, uint32_t start_data_cluster);

errval_t fat32_get_dir_at(struct fat32 *fs, uint32_t start_cluster, uint32_t index,
                                 struct fat32_dir_entry *dir);

errval_t fat32_set_dir_at(struct fat32 *fs, uint32_t start_cluster, uint32_t index,
                                 struct fat32_dir_entry *dir);


#endif