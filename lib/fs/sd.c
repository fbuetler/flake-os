#include <aos/aos.h>
#include <maps/imx8x_map.h>
#include <drivers/sdhc.h>
#include <aos/cache.h>
#include <fs/sd.h>

void *sd_mem_base;

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

errval_t init_phys_virt_addr(size_t bytes, struct phys_virt_addr *addr)
{
    addr->dirty = true;

    // get a frame first
    struct capref cap;
    errval_t err = frame_alloc(&cap, bytes, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "frame_alloc");
        return err;
    }

    // map it
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

errval_t sd_read_sector(struct sdhc_s *sd, uint32_t sector, struct phys_virt_addr *addr)
{
    if (addr->last_sector == sector && !addr->dirty) {
        return SYS_ERR_OK;
    } else {
        addr->last_sector = sector;
        addr->dirty = false;
    }
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    return sdhc_read_block(sd, sector, addr->phys);
}

errval_t sd_write_sector(struct sdhc_s *sd, uint32_t sector, struct phys_virt_addr *addr)
{
    arm64_dcache_wbinv_range((vm_offset_t)addr->virt, SDHC_BLOCK_SIZE);
    errval_t res = sdhc_write_block(sd, sector, addr->phys);
    addr->last_sector = sector;
    return res;
}


