#!/bin/bash

set -x # show cmds
set -e # fail globally

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

APK_PATH="$SCRIPTPATH/cache/$(uname -m)-apk-static"
APK_URI="https://gitlab.alpinelinux.org/api/v4/projects/5/packages/generic/v2.14.10/$(uname -m)/apk.static"

mkdir -p "$(dirname "$APK_PATH")"
[ -f "$APK_PATH" ] || wget "$APK_URI" -O "$APK_PATH"
chmod +x "$APK_PATH"

ALPINE_VERSION=edge

export APK_PATH ARCH ROOTFS_SYSROOT ALPINE_VERSION

MIRROR_ROOT="http://mirrors.ustc.edu.cn/alpine"

MIRROR="${MIRROR_ROOT}/${ALPINE_VERSION}"
APK_CMD="sudo $APK_PATH --arch $ARCH -U --allow-untrusted --root $ROOTFS_SYSROOT/"

$APK_CMD -X "$MIRROR/main" --initdb add alpine-base bash coreutils grep musl ncurses

printf "${MIRROR}/main\n${MIRROR}/community\n${MIRROR_ROOT}/edge/testing\n" | sudo tee $ROOTFS_SYSROOT/etc/apk/repositories

sudo cp -r $SCRIPTPATH/base/etc/resolv.conf $ROOTFS_SYSROOT/etc/

sudo chroot "$ROOTFS_SYSROOT/" /bin/bash --login -c "apk add musl-dev gcompat gzip xz make file tar pciutils tzdata nano vim lua5.1 gcc binutils fastfetch libdrm-dev libdrm-tests bind-tools curl evtest \
seatd seatd-launch dbus eudev \
weston weston-backend-drm weston-shell-desktop weston-xwayland xwayland ttf-dejavu \
weston-terminal \
mesa mesa-gl mesa-egl mesa-gles mesa-gbm mesa-utils mesa-vulkan-swrast mesa-dri-gallium"

sudo rm -rf $ROOTFS_SYSROOT/bin/sh
sudo ln -sf /bin/bash $ROOTFS_SYSROOT/bin/sh
sudo ln -sf /usr/share/zoneinfo/Asia/Shanghai $ROOTFS_SYSROOT/etc/localtime

sudo cp -r $SCRIPTPATH/base/* $ROOTFS_SYSROOT/

sudo chmod -R 700 $ROOTFS_SYSROOT/run
