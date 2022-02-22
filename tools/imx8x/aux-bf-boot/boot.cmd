echo Loading DeviceTree: ${fdtfile}
load mmc 0:1 ${fdt_addr_r} ${fdtfile}
fdt addr ${fdt_addr_r} && fdt resize 0x20000

load mmc 0:1 ${loadaddr} overlays.txt
env import -t ${loadaddr} ${filesize}
for overlay_file in ${fdt_overlays}; do
    echo Applying Overlay: ${overlay_file}
    load mmc 0:1 ${loadaddr} overlays/${overlay_file} && fdt apply ${loadaddr}
    env set overlay_file
done

bootefi ${kernel_addr_r} ${fdt_addr_r}

