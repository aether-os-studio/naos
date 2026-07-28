# NeoAether OS

This repository provides the userspace for `na-kernel` and orchestrates
the complete build without mixing userspace construction into the kernel tree.

To build, you should clone https://github.com/aether-os-studio/na-kernel to this folder

Run `make` to build the kernel, modules, initramfs, boot image and selected
rootfs. Individual targets are `kernel`, `modules`, `initramfs`, `image`, and
`rootfs`.

Select the rootfs implementation with `ROOTFS`. Each implementation has an
independent output directory:

```text
make rootfs ROOTFS=nixos       # build/x86_64/rootfs/nixos/rootfs.img
make rootfs ROOTFS=voidlinux   # build/x86_64/rootfs/voidlinux/rootfs.img
make rootfs ROOTFS=alpine ARCH=riscv64 # build/riscv64/rootfs/alpine/rootfs.img
```

`rootfs-nixos` and `rootfs-voidlinux` are convenience targets. `make run`
uses the same selection, for example `make run ROOTFS=voidlinux`. Void Linux
downloads are reused from `build/cache/voidlinux`, and the expanded rootfs is
kept in `build/$ARCH/rootfs/voidlinux/rootfs/` for incremental XBPS rebuilds.
Extra Void packages can be supplied with `VOID_PACKAGES='package1 package2'`.
The Void output is a raw ext filesystem image without a partition table, so it
can be mounted directly with `mount -o loop`.

`rootfs-alpine` is the Alpine convenience target. Alpine builds default to an
8192 MiB image using Alpine v3.23, with architecture-specific packages read
from `rootfs/alpine/packages-$ARCH.txt`. Override the defaults with
`ALPINE_ROOTFS_SIZE_MB`, `ALPINE_MIRROR`, `ALPINE_VERSION`,
`ALPINE_COMPAT_VERSION`, or `ALPINE_PACKAGES='package1 package2'`.
Downloaded APKs are reused from `build/cache/alpine`.

`make run` starts the x86_64 artifacts with QEMU and OVMF from the same local
Nix store.

Stage-1 detects the selected rootfs entry point. A different stage-2 entry
point can be supplied with the kernel command line `init=` option.

Use `make distclean` to remove both ordinary build outputs and the isolated Nix
store. `make clean` keeps `.nix-store` so downloaded Nix dependencies can be
reused.
