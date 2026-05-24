#!/bin/bash

set -x # show cmds
set -e # fail globally

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

APK_PATH="$SCRIPTPATH/cache/$(uname -m)-apk-static.apk"
APK_URI="http://mirror.sjtu.edu.cn/alpine/edge/main/x86_64/apk-tools-static-3.0.6-r0.apk"

mkdir -p "$SCRIPTPATH/cache/"
[ -f "$APK_PATH" ] || curl -Lo "$APK_PATH" "$APK_URI"
tar -xvf $APK_PATH -C "$SCRIPTPATH/cache/"
chmod +x "$APK_PATH"

ALPINE_VERSION=edge

MIRROR_ROOT="http://mirror.sjtu.edu.cn/alpine"

MIRROR="${MIRROR_ROOT}/${ALPINE_VERSION}"
APK_CMD="cache/sbin/apk.static $( [ "$(id -u)" -eq 0 ] || echo "--usermode" ) --arch $ARCH -U --allow-untrusted --root $SYSROOT/"

$APK_CMD -X "$MIRROR/main" --initdb add busybox
