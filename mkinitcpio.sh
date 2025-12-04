mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/bin/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/dev/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/mnt/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/proc/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/sbin/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/run/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/sys/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/tmp/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/var/
mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/lib/modules/

sudo cp -r ${PROJECT_ROOT}/user/rootfs-${ARCH}/bin/busybox ${PROJECT_ROOT}/initramfs-${ARCH}/bin
sudo cp -r ${PROJECT_ROOT}/user/rootfs-${ARCH}/lib/ld-musl-x86_64.so.1 ${PROJECT_ROOT}/initramfs-${ARCH}/lib

# Create /bin/*
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/arch"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/ash"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/base32"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/base64"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/cat"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/chattr"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/chgrp"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/chmod"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/chown"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/cp"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/cpio"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/echo"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/false"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/grep"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/ls"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/mkdir"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/mount"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/mv"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/ps"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/sh"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/true"
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/bin/umount"

# Create /sbin/*
ln -sf /bin/busybox "${PROJECT_ROOT}/initramfs-${ARCH}/sbin/switch_root"

# Copy init script
cp -r ${PROJECT_ROOT}/init ${PROJECT_ROOT}/initramfs-${ARCH}/

# Copy modules
cp ${PROJECT_ROOT}/modules-${ARCH}/* ${PROJECT_ROOT}/initramfs-${ARCH}/lib/modules/

cd ${PROJECT_ROOT}/initramfs-${ARCH}

# Make initramfs.img
find . -print | cpio -o -H newc >${PROJECT_ROOT}/initramfs-${ARCH}.img

cd ${PROJECT_ROOT}/
