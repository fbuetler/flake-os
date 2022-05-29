#ifndef __FS_SD_H__
#define __FS_SD_H__

#include <aos/aos.h>

struct phys_virt_addr {
    lpaddr_t phys;
    void *virt;

    /**
     * @brief Contains the last sector that has been written/read into this buffer
     * Assumes all reads/writs towards phys/virt are done using the same phys_virt_addr
     * instance!
     *
     * Also assumes nobody writes to virt without also writing back to the disk
     *
     * This is used to avoid unnecessary reads to buffer
     */
    uint32_t last_sector;
    bool dirty;
};

errval_t init_sd(struct sdhc_s **sd);

errval_t init_phys_virt_addr(size_t bytes, struct phys_virt_addr *addr);

errval_t sd_read_sector(struct sdhc_s *sd, uint32_t sector, struct phys_virt_addr *addr);

errval_t sd_write_sector(struct sdhc_s *sd, uint32_t sector, struct phys_virt_addr *addr);



#endif