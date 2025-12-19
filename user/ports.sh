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

ALPINE_VERSION=v3.22

# Export variables needed for the unshare'd environment
export APK_PATH ARCH SYSROOT ALPINE_VERSION

# Use a fast mirror :)
MIRROR_ROOT="http://mirrors.ustc.edu.cn/alpine"

MIRROR="${MIRROR_ROOT}/${ALPINE_VERSION}"
APK_CMD="sudo $APK_PATH --arch $ARCH -U --allow-untrusted --root $SYSROOT/"

# Bootstrap alpine userspace
$APK_CMD -X "$MIRROR/main" -U --initdb add alpine-base bash coreutils grep musl ncurses

printf "${MIRROR}/main\n${MIRROR}/community\n" | sudo tee $SYSROOT/etc/apk/repositories

sudo rm -rf $SYSROOT/bin/sh
sudo ln -sf /bin/bash $SYSROOT/bin/sh
sudo ln -sf /usr/share/zoneinfo/Asia/Shanghai $SYSROOT/etc/localtime

sudo rm -rf $SYSROOT/etc/conf.d/*
sudo rm -rf $SYSROOT/etc/init.d/*

sudo chmod -R 700 $SYSROOT/run
