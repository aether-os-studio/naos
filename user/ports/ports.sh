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

# bootstrap alpine userspace
sudo "$APK_PATH" --arch $ARCH -X http://mirrors.ustc.edu.cn/alpine/latest-stable/main/ -U --allow-untrusted --root $SYSROOT/../ --initdb add alpine-base bash coreutils tzdata procps vim findutils diffutils patch grep sed gawk gzip xz make file tar nasm python3 gcc musl-dev pciutils

sudo chmod -R 777 $SYSROOT/../

find $SYSROOT/../etc -type l -delete
find $SYSROOT/../usr -type l -delete
find $SYSROOT/../bin -type l -delete
find $SYSROOT/../sbin -type l -delete

cp -r $SCRIPTPATH/etc $SYSROOT/../
cp $SYSROOT/../usr/lib/libreadline.so.8.2 $SYSROOT/../usr/lib/libreadline.so.8
cp $SYSROOT/../usr/lib/libncursesw.so.6.5 $SYSROOT/../usr/lib/libncursesw.so.6
