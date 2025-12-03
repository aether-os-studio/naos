mkdir -p ${PROJECT_ROOT}/initramfs-${ARCH}/lib/modules/
cp ${PROJECT_ROOT}/modules-${ARCH}/* ${PROJECT_ROOT}/initramfs-${ARCH}/lib/modules/
cd ${PROJECT_ROOT}/initramfs-${ARCH}
find . -name "*.ko" -print | cpio -o -H newc > ${PROJECT_ROOT}/initramfs-${ARCH}.img
cd ${PROJECT_ROOT}/
