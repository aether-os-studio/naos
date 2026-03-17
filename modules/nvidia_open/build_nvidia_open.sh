if [ ! -d $PROJECT_ROOT/nvidia-open ]; then
    git clone  --depth=1 https://github.com/aether-os-studio/nvidia-open.git $PROJECT_ROOT/nvidia-open
    cd $PROJECT_ROOT/nvidia-open
    git am $PROJECT_ROOT/modules/nvidia_open/0001-Add-managarm-support.patch
    cd $PROJECT_ROOT/modules/nvidia_open
fi

unset CFLAGS

FLAGS="-g3 -O0 -fPIC -fvisibility=hidden -fno-stack-protector -D__managarm__"

if [ ! -d $PROJECT_ROOT/nvidia-open-install-dir ]; then
    cd $PROJECT_ROOT/nvidia-open
    mkdir -p _out
    cd _out
    CFLAGS=${FLAGS} CPPFLAGS=${FLAGS} meson setup .. --prefix=/usr
    ninja -j$(nproc)
    DESTDIR=$PROJECT_ROOT/nvidia-open-install-dir ninja install
fi
