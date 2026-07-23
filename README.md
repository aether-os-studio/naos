# NeoAether OS

This repository provides the userspace for `na-kernel` and orchestrates
the complete build without mixing userspace construction into the kernel tree.

To build, you should clone https://github.com/aether-os-studio/na-kernel to this folder

Run `make` to build the kernel, modules, initramfs, boot image and NixOS rootfs.
Outputs are placed in `build/$ARCH/`. Individual targets are `kernel`,
`modules`, `initramfs`, `image`, and `rootfs`.

`make run` starts the x86_64 artifacts with QEMU and OVMF from the same local
Nix store.

Stage-1 switches to `/nix/var/nix/profiles/system/init` by default. A different
stage-2 entry point can be supplied with the kernel command line `init=` option.

Use `make distclean` to remove both ordinary build outputs and the isolated Nix
store. `make clean` keeps `.nix-store` so downloaded Nix dependencies can be
reused.
