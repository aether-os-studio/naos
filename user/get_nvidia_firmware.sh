if [ ! -f cache/NVIDIA-Linux-x86_64-575.51.02.run ]; then
    wget https://download.nvidia.com/XFree86/Linux-x86_64/575.51.02/NVIDIA-Linux-x86_64-575.51.02.run -O cache/NVIDIA-Linux-x86_64-575.51.02.run
    chmod a+x cache/NVIDIA-Linux-x86_64-575.51.02.run
fi

if [ ! -d cache/extracted/firmware ]; then
    ./cache/NVIDIA-Linux-x86_64-575.51.02.run --extract-only --target ./cache/extracted
fi

sudo mkdir -p rootfs-${ARCH}/lib/firmware/nvidia/575.51.02/
if [ ! -f initramfs-${ARCH}/lib/firmware/nvidia/575.51.02/gsp_ga10x.bin ]; then
    sudo cp cache/extracted/firmware/gsp_ga10x.bin rootfs-${ARCH}/lib/firmware/nvidia/575.51.02/
fi
if [ ! -f initramfs-${ARCH}/lib/firmware/nvidia/575.51.02/gsp_tu10x.bin ]; then
    sudo cp cache/extracted/firmware/gsp_tu10x.bin rootfs-${ARCH}/lib/firmware/nvidia/575.51.02/
fi
