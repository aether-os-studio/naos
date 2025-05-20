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
sudo "$APK_PATH" --arch $ARCH -X http://mirrors.ustc.edu.cn/alpine/latest-stable/main -U --allow-untrusted --root $SYSROOT/../ --initdb add alpine-base bash coreutils grep musl ncurses
echo -e "http://mirrors.ustc.edu.cn/alpine/latest-stable/main\nhttp://mirrors.ustc.edu.cn/alpine/latest-stable/community" | sudo tee $SYSROOT/../etc/apk/repositories

# Basic software
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add musl-dev nano gzip xz make file tar pciutils tzdata
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add nano
sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add lua5.1 gcc binutils
# sudo "$APK_PATH" --arch $ARCH -U --allow-untrusted --root $SYSROOT/../ --initdb add weston weston-backend-fbdev weston-shell-desktop

# if [ ! -f $SYSROOT/bin/weston ]; then
#     sudo docker run -it --rm -v $ROOT_DIR:/docker alpine:latest /bin/sh -c "apk add gcc meson ninja-build samurai && sh /docker/user/ports/build_weston.sh"
# fi

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
