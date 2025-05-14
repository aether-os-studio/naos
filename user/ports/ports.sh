#!/bin/bash
set -x # show cmds
set -e # fail globally

# Know where we at :p
SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# APK package manager (host)
APK_PATH="$HOME/opt/apk-static"
APK_URI="https://gitlab.alpinelinux.org/api/v4/projects/5/packages/generic/v2.14.6/x86_64/apk.static"
APK_SHA512="782b29d10256ad07fbdfa9bf1b2ac4df9a9ae7162c836ee0ecffc991a4f75113512840f7b3959f5deb81f1d6042c15eeb407139896a8a02c57060de986489e7a"
chmod +x "${SCRIPTPATH}/pass_acq.sh"
${SCRIPTPATH}/pass_acq.sh "$APK_URI" "$APK_SHA512" "$APK_PATH"
chmod +x "$APK_PATH"

ALPINE_VERSION=v3.20

# bootstrap alpine userspace
sudo "$APK_PATH" --arch $ARCH -X http://mirrors.ustc.edu.cn/alpine/$ALPINE_VERSION/main -U --allow-untrusted --root $SYSROOT/../ --initdb add alpine-base bash coreutils grep musl ncurses
echo -e "http://mirrors.ustc.edu.cn/alpine/$ALPINE_VERSION/main\nhttp://mirrors.ustc.edu.cn/alpine/$ALPINE_VERSION/community" | sudo tee $SYSROOT/../etc/apk/repositories

# Basic software
sudo "$APK_PATH" --arch $ARCH -X http://mirrors.ustc.edu.cn/alpine/$ALPINE_VERSION/community -U --allow-untrusted --root $SYSROOT/../ --initdb add xorg-server xf86-video-fbdev xf86-input-evdev twm xterm xinit xsetroot xeyes xclock

sudo chmod -R 777 $SYSROOT/../

cp -r /usr/share/zoneinfo/Asia/Shanghai $SYSROOT/../etc/localtime

find $SYSROOT/../ -type l -exec bash -c '
    lnk="{}";
    target=$(readlink -f "$lnk");
    if [ -f "$target" ]; then
        rm "$lnk";
        cp -- "$target" "$lnk"; 
    else
        rm "$lnk";
    fi
' \;

cp -r $SCRIPTPATH/etc $SYSROOT/../
cp -r $SCRIPTPATH/root $SYSROOT/../
cp -r $SCRIPTPATH/files $SYSROOT/../

cp -r $SYSROOT/../bin/bash $SYSROOT/../bin/sh

cp -r $SYSROOT/lib/xorg/modules/libfbdevhw.so $SYSROOT/lib/xorg/modules/extensions/libfbdevhw.so
