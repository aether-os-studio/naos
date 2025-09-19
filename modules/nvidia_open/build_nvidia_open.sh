if [ ! -d ../../nvidia-open ]; then
    git clone https://github.com/aether-os-studio/nvidia-open.git ../../nvidia-open
fi

unset CFLAGS

FLAGS="-g3 -O0 -fPIC -fvisibility=hidden"

if [ ! -d ${NVIDIA_OPEN_ROOT}/../../nvidia-open-install-dir ]; then
    cd ../../nvidia-open
    mkdir -p _out
    cd _out
    CFLAGS=${FLAGS} CPPFLAGS=${FLAGS} meson setup .. --prefix=/usr
    ninja -j$(nproc)
    DESTDIR=${NVIDIA_OPEN_ROOT}/../../nvidia-open-install-dir ninja install
fi
