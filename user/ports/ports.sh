#!/bin/bash
set -x # show cmds
set -e # fail globally

# Know where we at :p
SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# APK package manager (host)
APK_PATH="$HOME/opt/$ARCH-apk-static"
APK_URI="https://gitlab.alpinelinux.org/api/v4/projects/5/packages/generic/v2.14.6/$ARCH/apk.static"
if [ ! -f $APK_PATH ]; then
    wget $APK_URI -O $APK_PATH
fi
chmod +x "$APK_PATH"

ALPINE_VERSION=v3.14

# bootstrap alpine userspace
sudo "$APK_PATH" --arch $ARCH -X http://mirrors.ustc.edu.cn/alpine/${ALPINE_VERSION}/main -U --allow-untrusted --root $SYSROOT/../ --initdb add alpine-base bash coreutils grep musl ncurses
echo "http://mirrors.ustc.edu.cn/alpine/${ALPINE_VERSION}/main\nhttp://mirrors.ustc.edu.cn/alpine/${ALPINE_VERSION}/community" | sudo tee $SYSROOT/../etc/apk/repositories

# Basic software
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add musl-dev gcompat gzip xz make file tar pciutils tzdata
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add nano
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add lua5.1 gcc binutils
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add seatd weston weston-backend-fbdev weston-shell-desktop

sudo cp -r $SYSROOT/share/zoneinfo/Asia/Shanghai $SYSROOT/../etc/localtime

sudo chmod -R 777 $SYSROOT/../

# find $SYSROOT/../ -type l -exec bash -c '
#     lnk="{}";
#     target=$(readlink -f "$lnk");
#     if [ -f "$target" ]; then
#         rm "$lnk";
#         cp -- "$target" "$lnk";
#     else
#         rm "$lnk";
#     fi
# ' \;

cp -r $SCRIPTPATH/etc $SYSROOT/../
cp -r $SCRIPTPATH/root $SYSROOT/../
cp -r $SCRIPTPATH/files $SYSROOT/../
