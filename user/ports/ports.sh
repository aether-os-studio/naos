#!/bin/bash
set -x # show cmds
set -e # fail globally

# Know where we at :p
SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# APK package manager (local cache)
APK_PATH="$SCRIPTPATH/cache/$(uname -m)-apk-static"
APK_URI="https://gitlab.alpinelinux.org/api/v4/projects/5/packages/generic/v2.14.10/$(uname -m)/apk.static"

# Download the APK static binary
mkdir -p "$(dirname "$APK_PATH")"
[ -f "$APK_PATH" ] || wget "$APK_URI" -O "$APK_PATH"
chmod +x "$APK_PATH"

ALPINE_VERSION=latest-stable

# Export variables needed for the unshare'd environment
export APK_PATH ARCH SYSROOT ALPINE_VERSION

# Use unshare to perform privileged operations
unshare -r -- /bin/bash -c '
set -xe

MIRROR_ROOT="http://mirrors.ustc.edu.cn/alpine"

MIRROR="${MIRROR_ROOT}/${ALPINE_VERSION}"
APK_CMD="$APK_PATH --arch $ARCH -U --allow-untrusted --root $SYSROOT/../"

# Bootstrap alpine userspace
$APK_CMD -X "$MIRROR/main" -U --initdb add alpine-base bash coreutils grep musl ncurses

# Use a fast mirror :)
printf "${MIRROR}/main\n${MIRROR}/community\n${MIRROR_ROOT}/edge/testing" > $SYSROOT/../etc/apk/repositories

$APK_CMD add musl-dev gcompat gzip xz make file tar pciutils tzdata nano lua5.1 gcc binutils python3 libdrm-tests curl sysbench
# $APK_CMD add seatd weston weston-backend-drm weston-shell-desktop
# $APK_CMD add xorg-server xf86-video-fbdev xf86-input-evdev xinit xsetroot twm
# $APK_CMD add mesa-gl mesa-utils mesa-vulkan-swrast mesa-dri-gallium

ln -sf $SYSROOT/../usr/share/zoneinfo/Asia/Shanghai $SYSROOT/../etc/localtime
'

rm -rf $SYSROOT/../bin/sh
ln -sf bash $SYSROOT/../bin/sh

rm -rf $SYSROOT/../etc/init.d/*
rm -rf $SYSROOT/../etc/conf.d/*

cp -r $SCRIPTPATH/etc $SYSROOT/../
cp -r $SCRIPTPATH/root $SYSROOT/../

# Make us able to read the files later
chmod -R u+r $SYSROOT/../
