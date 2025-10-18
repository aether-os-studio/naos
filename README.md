# The Neo Aether Operating system

![Screenshot](./images/aether-xeyes-xclock.png?raw=true)

## What is this about?

This is the main repository of neo-aether-os, a linux compatable operating system.

## Features

* 64-bit operating system with SMP (i.e., multicore) and ACPI support.
* Support for many modern hardware devices such as USB XHCI controllers.
* Networking support.
* POSIX and Linux API compatibility.
* Support for Linux-style special files (epoll, signalfd, ...) and pseudo file systems (`/sys`, `/proc`, ...).

## Supported Software

Programs supported on aether-os include [Weston](https://gitlab.freedesktop.org/wayland/weston/) (the Wayland reference compositor), Busybox, Coreutils, Bash, nano, vim and others.

## Supported Hardware

**General** USB (XHCI)\
**Graphics** virtio GPU, VMWare SVGA\
**Input** USB human interface devices, PS/2 keyboard and mouse\
**Storage** USB mass storage devices, NVMe, AHCI, virtio block\
**Network** E1000, virtio network

## Running aether-os

Running `make run` will build the kernel and a bootable image and a rootfs image, and then run it using `qemu` (if installed).
