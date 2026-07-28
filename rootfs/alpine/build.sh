#!/bin/sh

set -eu

: "${ARCH:?ARCH is required}"
: "${OUTPUT:?OUTPUT is required}"

ROOTFS_SIZE_MB=${ROOTFS_SIZE_MB:-8192}
ALPINE_MIRROR_ROOT=${ALPINE_MIRROR_ROOT:-https://mirrors.tuna.tsinghua.edu.cn/alpine}
ALPINE_VERSION=${ALPINE_VERSION:-v3.23}
ALPINE_COMPAT_VERSION=${ALPINE_COMPAT_VERSION:-v3.20}
ALPINE_APK_TOOLS_VERSION=${ALPINE_APK_TOOLS_VERSION:-3.0.6-r0}
ALPINE_PACKAGES=${ALPINE_PACKAGES:-}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
packages_file="$script_dir/packages.txt"
arch_packages_file="$script_dir/packages-$ARCH.txt"
overlay_dir="$script_dir/overlay"
output_dir=$(dirname -- "$OUTPUT")

case "$ARCH" in
  x86_64)
    apk_arch=x86_64
    ;;
  aarch64)
    apk_arch=aarch64
    ;;
  riscv64)
    apk_arch=riscv64
    ;;
  loongarch64)
    apk_arch=loongarch64
    ;;
  *)
    echo "Alpine rootfs 暂不支持架构: $ARCH" >&2
    exit 2
    ;;
esac

host_arch=$(uname -m)
case "$host_arch" in
  x86_64|aarch64)
    apk_tools_arch=$host_arch
    ;;
  *)
    echo "apk.static 暂不支持当前构建主机: $host_arch" >&2
    exit 2
    ;;
esac

# 交叉构建时不能在宿主机执行目标架构的安装脚本。
apk_script_args=
if [ "$apk_arch" != "$host_arch" ]; then
  apk_script_args="--scripts=no"
fi

case "$ROOTFS_SIZE_MB" in
  ''|*[!0-9]*)
    echo "ROOTFS_SIZE_MB 必须是正整数" >&2
    exit 2
    ;;
esac
if [ "$ROOTFS_SIZE_MB" -le 1024 ]; then
  echo "ROOTFS_SIZE_MB 过小: $ROOTFS_SIZE_MB" >&2
  exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
  sudo=
else
  sudo=${SUDO:-sudo}
fi

tool_cache_dir="$project_root/build/cache/alpine/$host_arch"
package_cache_dir="$project_root/build/cache/alpine/packages/$apk_arch"
compat_cache_dir="$package_cache_dir/compat"

mkdir -p "$tool_cache_dir" "$package_cache_dir" "$compat_cache_dir" "$output_dir"

# apk.static 在 Linux 临时目录展开文件，避免 WSL 挂载盘的链接和权限语义影响 rootfs。
rootfs_dir=$(mktemp -d "${TMPDIR:-/tmp}/naos-alpine-rootfs.XXXXXX")
image_tmp="$OUTPUT.tmp.$$"
cleanup() {
  rm -f "$image_tmp"
  $sudo rm -rf -- "$rootfs_dir"
}
trap cleanup EXIT INT TERM

# 下载并缓存当前构建主机使用的 apk.static。
apk_static_path="$tool_cache_dir/apk-tools-static.apk"
apk_extract_dir="$tool_cache_dir/apk"
apk_url="$ALPINE_MIRROR_ROOT/$ALPINE_VERSION/main/$apk_tools_arch/apk-tools-static-$ALPINE_APK_TOOLS_VERSION.apk"

if [ ! -f "$apk_static_path" ]; then
  curl -L --fail -o "$apk_static_path.tmp" "$apk_url"
  mv "$apk_static_path.tmp" "$apk_static_path"
fi

if [ ! -d "$apk_extract_dir" ]; then
  apk_extract_tmp="$apk_extract_dir.tmp.$$"
  rm -rf -- "$apk_extract_tmp"
  mkdir -p "$apk_extract_tmp"
  tar -xf "$apk_static_path" -C "$apk_extract_tmp"
  mv "$apk_extract_tmp" "$apk_extract_dir"
fi

apk_static="$apk_extract_dir/sbin/apk.static"
if [ ! -x "$apk_static" ]; then
  echo "解压后未找到 apk.static" >&2
  exit 1
fi

ALPINE_MIRROR="$ALPINE_MIRROR_ROOT/$ALPINE_VERSION"
ALPINE_EDGE_MIRROR="$ALPINE_MIRROR_ROOT/edge"

$sudo mkdir -p "$rootfs_dir"

# 安装两个架构共用的软件包，再追加架构专用包。
packages=$(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$packages_file")
arch_packages=
if [ -f "$arch_packages_file" ]; then
  arch_packages=$(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$arch_packages_file")
fi
# shellcheck disable=SC2086
$sudo "$apk_static" \
  --arch "$apk_arch" \
  -U \
  --allow-untrusted \
  $apk_script_args \
  --root "$rootfs_dir" \
  --cache-dir "$package_cache_dir" \
  --cache-packages \
  -X "$ALPINE_MIRROR/main" \
  -X "$ALPINE_MIRROR/community" \
  --initdb add \
  $packages $arch_packages $ALPINE_PACKAGES

# 两个架构使用同一套已验证的 Wayland/XFCE 版本。
$sudo "$apk_static" \
  --arch "$apk_arch" \
  -U \
  --allow-untrusted \
  $apk_script_args \
  --root "$rootfs_dir" \
  --cache-dir "$package_cache_dir" \
  --cache-packages \
  -X "$ALPINE_MIRROR/main" \
  -X "$ALPINE_MIRROR/community" \
  -X "$ALPINE_EDGE_MIRROR/main" \
  -X "$ALPINE_EDGE_MIRROR/community" \
  add \
  labwc=0.20.1-r0 \
  libxfce4windowing=4.20.6-r0 \
  xfdesktop=4.20.2-r0

# 使用旧版图像加载栈，避开当前 Glycin/bwrap 在 Aether-OS 上的兼容问题。
ALPINE_COMPAT_MIRROR="$ALPINE_MIRROR_ROOT/$ALPINE_COMPAT_VERSION"
compat_packages="gdk-pixbuf=2.42.12-r0"
if [ "$ARCH" = riscv64 ]; then
  compat_packages="$compat_packages gtk+3.0=3.24.43-r0 librsvg=2.58.5-r0"
fi

# shellcheck disable=SC2086
$sudo "$apk_static" \
  --arch "$apk_arch" \
  -U \
  --allow-untrusted \
  $apk_script_args \
  --root "$rootfs_dir" \
  --cache-dir "$compat_cache_dir" \
  --cache-packages \
  -X "$ALPINE_COMPAT_MIRROR/main" \
  -X "$ALPINE_COMPAT_MIRROR/community" \
  add \
  $compat_packages

# 应用两个架构共用的 Aether-OS 用户态配置。
$sudo cp -a "$overlay_dir/." "$rootfs_dir/"

# apk.static 未运行安装脚本时，补齐基础账户信息。
if [ ! -f "$rootfs_dir/etc/passwd" ]; then
  printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' | \
    $sudo tee "$rootfs_dir/etc/passwd" >/dev/null
fi
if [ ! -f "$rootfs_dir/etc/group" ]; then
  printf 'root:x:0:root\nnobody:x:65534:\n' | \
    $sudo tee "$rootfs_dir/etc/group" >/dev/null
fi

# 交叉构建跳过了账户创建脚本，手动补齐桌面服务需要的账户。
if ! grep -q '^messagebus:' "$rootfs_dir/etc/passwd"; then
  printf '%s\n' 'messagebus:x:100:101:messagebus:/dev/null:/sbin/nologin' | \
    $sudo tee -a "$rootfs_dir/etc/passwd" >/dev/null
fi
if ! grep -q '^polkitd:' "$rootfs_dir/etc/passwd"; then
  printf '%s\n' 'polkitd:x:101:102:polkitd:/var/empty:/sbin/nologin' | \
    $sudo tee -a "$rootfs_dir/etc/passwd" >/dev/null
fi
if ! grep -q '^messagebus:' "$rootfs_dir/etc/group"; then
  printf '%s\n' 'messagebus:x:101:messagebus' | \
    $sudo tee -a "$rootfs_dir/etc/group" >/dev/null
fi
if ! grep -q '^polkitd:' "$rootfs_dir/etc/group"; then
  printf '%s\n' 'polkitd:x:102:polkitd' | \
    $sudo tee -a "$rootfs_dir/etc/group" >/dev/null
fi

# 保留稳定版仓库作为系统默认软件源。
printf '%s\n' "$ALPINE_MIRROR/main" "$ALPINE_MIRROR/community" | \
  $sudo tee "$rootfs_dir/etc/apk/repositories" >/dev/null

# 设置启动脚本和账户文件权限。
$sudo chmod 0755 \
  "$rootfs_dir/usr/lib/aether/init" \
  "$rootfs_dir/usr/lib/aether/start-xfce4-session"
$sudo chmod 0440 "$rootfs_dir/etc/sudoers"
$sudo chmod 0400 "$rootfs_dir/etc/shadow"

$sudo ln -snf /usr/lib/aether/init "$rootfs_dir/sbin/init"
$sudo ln -snf lua5.4 "$rootfs_dir/usr/bin/lua"
$sudo ln -snf /usr/share/zoneinfo/Asia/Shanghai "$rootfs_dir/etc/localtime"

if [ "$apk_arch" = "$host_arch" ]; then
  $sudo chroot "$rootfs_dir" /usr/sbin/usermod -s /bin/bash root 2>/dev/null || \
    $sudo sed -i 's|^root:.*:/bin/sh$|root:x:0:0:root:/root:/bin/bash|' "$rootfs_dir/etc/passwd"
else
  $sudo sed -i 's|^root:.*:/bin/sh$|root:x:0:0:root:/root:/bin/bash|' "$rootfs_dir/etc/passwd"
fi

# 补齐运行时目录。
$sudo mkdir -p \
  "$rootfs_dir/dev" "$rootfs_dir/proc" "$rootfs_dir/sys" \
  "$rootfs_dir/run" "$rootfs_dir/tmp"
$sudo chmod 01777 "$rootfs_dir/tmp"

# 镜像内不保留下载缓存，宿主机缓存仍按目标架构保存。
$sudo rm -rf "$rootfs_dir/var/cache/apk"/*

# 生成与 Void 构建流程一致的 ext4 rootfs 镜像。
truncate -s "${ROOTFS_SIZE_MB}M" "$image_tmp"
$sudo mkfs.ext4 -q -F -b 1024 -I 256 \
  -O extent,64bit,flex_bg,huge_file,dir_nlink,extra_isize,dir_index,metadata_csum,^has_journal,^quota,^metadata_csum_seed,^orphan_file,^project,^encrypt,^verity,^casefold,^inline_data,^ea_inode,^bigalloc,^mmp,^fast_commit,^sparse_super2 \
  -E lazy_itable_init=0 \
  -L naos-rootfs -d "$rootfs_dir" "$image_tmp"

chmod 0644 "$image_tmp"
mv -f "$image_tmp" "$OUTPUT"
