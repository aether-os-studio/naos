mkdir -p meta-sources/base-files/dev
mkdir -p meta-sources/base-files/etc
mkdir -p meta-sources/base-files/home
mkdir -p meta-sources/base-files/proc
mkdir -p meta-sources/base-files/root
mkdir -p meta-sources/base-files/run
mkdir -p meta-sources/base-files/sys
mkdir -p meta-sources/base-files/tmp
mkdir -p meta-sources/base-files/usr/bin
mkdir -p meta-sources/base-files/usr/sbin
mkdir -p meta-sources/base-files/usr/lib
mkdir -p meta-sources/base-files/var

if [ ! -d rootfs-${ARCH}/bin ]; then
    ln -sf /usr/bin rootfs-${ARCH}/bin
fi

if [ ! -d rootfs-${ARCH}/lib ]; then
    ln -sf /usr/lib rootfs-${ARCH}/lib
fi
