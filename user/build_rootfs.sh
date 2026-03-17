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
[ -d "$XBPS_INSTALL_PATH" ] || tar -xf $XBPS_XZ_PATH -C $XBPS_INSTALL_PATH

sudo XBPS_ARCH=$ARCH $XBPS_INSTALL_PATH/usr/bin/xbps-install -S -r $ROOTFS_SYSROOT -R "https://mirrors.tuna.tsinghua.edu.cn/voidlinux/current" base-minimal bash fastfetch coreutils util-linux gcc binutils glibc-locales ncurses tzdata which shadow grep elfutils seatd eudev dbus weston xorg-server-xwayland mesa mesa-dri mesa-demos dejavu-fonts-ttf

sudo ln -sf /usr/share/zoneinfo/Asia/Shanghai $ROOTFS_SYSROOT/etc/localtime

sudo cp -r $SCRIPTPATH/base/* $ROOTFS_SYSROOT/

sudo $XBPS_INSTALL_PATH/usr/bin/xbps-reconfigure -r $ROOTFS_SYSROOT/ -f glibc-locales
