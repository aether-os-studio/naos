if [ ! -f cache/NVIDIA-Linux-x86_64-575.51.02.run ]; then
    wget https://download.nvidia.com/XFree86/Linux-x86_64/575.51.02/NVIDIA-Linux-x86_64-575.51.02.run -O cache/NVIDIA-Linux-x86_64-575.51.02.run
    chmod a+x cache/NVIDIA-Linux-x86_64-575.51.02.run
fi

if [ ! -d cache/extracted/firmware ]; then
    ./cache/NVIDIA-Linux-x86_64-575.51.02.run --extract-only --target ./cache/extracted
    sudo mkdir -p ${SYSROOT}/usr/lib/firmware/nvidia/575.51.02/
    sudo cp cache/extracted/firmware/gsp_ga10x.bin ${SYSROOT}/usr/lib/firmware/nvidia/575.51.02/
    sudo cp cache/extracted/firmware/gsp_tu10x.bin ${SYSROOT}/usr/lib/firmware/nvidia/575.51.02/
fi
