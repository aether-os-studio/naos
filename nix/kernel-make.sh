#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
kernel_dir="$project_root/na-kernel"
store_root="${NA_NIX_STORE_ROOT:-$project_root/.nix-store}"

exec nix --extra-experimental-features "nix-command flakes" \
  --store "local?root=$store_root" \
  develop "git+file://$kernel_dir" \
  -c make "$@"
