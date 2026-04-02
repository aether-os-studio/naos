#!/bin/bash

set -x # show cmds
set -e # fail globally

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

XBPS_INSTALL_PATH="$SCRIPTPATH/cache/xbps"
XBPS_XZ_PATH="$SCRIPTPATH/cache/xbps-static-latest.tar.xz"
XBPS_XZ_URI="https://repo-default.voidlinux.org/static/xbps-static-latest.$(uname -m)-musl.tar.xz"

mkdir -p "$(dirname "$XBPS_XZ_PATH")"
[ -f "$XBPS_XZ_PATH" ] || wget "$XBPS_XZ_URI" -O "$XBPS_XZ_PATH"

mkdir -p "$(dirname "$XBPS_INSTALL_PATH")"
[ -d "$XBPS_INSTALL_PATH" ] || mkdir -p "$XBPS_INSTALL_PATH" && tar -xf $XBPS_XZ_PATH -C $XBPS_INSTALL_PATH

[ $ARCH == aarch64 ] && export ARCH_SPEC=aarch64

sudo XBPS_ARCH=$ARCH $XBPS_INSTALL_PATH/usr/bin/xbps-install -S -r $ROOTFS_SYSROOT -R "https://mirrors.tuna.tsinghua.edu.cn/voidlinux/current/$ARCH_SPEC" \
    base-minimal bash coreutils util-linux \
    gcc binutils make \
    glibc-locales ncurses tzdata which shadow grep elfutils curl \
    seatd eudev dbus weston xorg-server-xwayland xrandr \
    fastfetch mesa mesa-dri mesa-demos lite-xl qemu-system-amd64 netsurf \
    adwaita-icon-theme dejavu-fonts-ttf

sudo ln -sf /usr/share/zoneinfo/Asia/Shanghai $ROOTFS_SYSROOT/etc/localtime

sudo cp -r $SCRIPTPATH/base/* $ROOTFS_SYSROOT/
