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

export APK_PATH ARCH SYSROOT ALPINE_VERSION

MIRROR_ROOT="http://mirrors.ustc.edu.cn/alpine"

MIRROR="${MIRROR_ROOT}/${ALPINE_VERSION}"
APK_CMD="sudo $APK_PATH --arch $ARCH -U --allow-untrusted --root $SYSROOT/"

$APK_CMD -X "$MIRROR/main" --initdb add busybox
