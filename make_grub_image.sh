LOOP_DEVICE=$(sudo losetup --find --show -P "$1")
sleep 1
sudo mkdir -p assets/multiboot2_boot_root
sudo mount -t vfat ${LOOP_DEVICE}p1 assets/multiboot2_boot_root
if [ ! -d assets/multiboot2_boot_root/boot ]; then
    sudo grub-install --target=x86_64-efi --efi-directory=assets/multiboot2_boot_root --boot-directory=assets/multiboot2_boot_root/boot --removable
fi
sudo umount assets/multiboot2_boot_root
sudo losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=""
