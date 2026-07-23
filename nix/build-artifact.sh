#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 {rootfs|initramfs} ARCH OUTPUT" >&2
  exit 2
fi

artifact="$1"
arch="$2"
output="$3"
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
store_root="${NA_NIX_STORE_ROOT:-$project_root/.nix-store}"

case "$arch" in
  x86_64) nix_system=x86_64-linux ;;
  aarch64) nix_system=aarch64-linux ;;
  riscv64) nix_system=riscv64-linux ;;
  loongarch64) nix_system=loongarch64-linux ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

mkdir -p "$store_root" "$(dirname -- "$output")"
if [ "$artifact" = initramfs ]; then
  modules="$project_root/na-kernel/modules-$arch"
  [ -d "$modules" ] || {
    echo "kernel modules have not been built: $modules" >&2
    exit 1
  }
  export NA_KERNEL_MODULES="$modules"
fi

logical_output=$(
  nix --extra-experimental-features "nix-command flakes" \
    --store "local?root=$store_root" \
    build --impure --no-link --print-out-paths \
    "path:$project_root/nix#packages.$nix_system.$artifact"
)
physical_output="$store_root$logical_output"

case "$artifact" in
  rootfs)
    source_image=$(find "$physical_output" -type f -name '*.img' -print -quit)
    [ -n "$source_image" ] || {
      echo "NixOS rootfs derivation produced no disk image" >&2
      exit 1
    }
    ;;
  initramfs) source_image="$physical_output/initramfs.img" ;;
  *) echo "unsupported artifact: $artifact" >&2; exit 2 ;;
esac

temporary_output="$output.tmp.$$"
trap 'rm -f "$temporary_output"' EXIT INT TERM
cp --reflink=auto --sparse=always "$source_image" "$temporary_output"
chmod 0644 "$temporary_output"
mv -f "$temporary_output" "$output"
trap - EXIT INT TERM
