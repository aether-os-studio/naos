#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
store_root="${NA_NIX_STORE_ROOT:-$project_root/.nix-store}"

exec nix --extra-experimental-features "nix-command flakes" \
  --store "local?root=$store_root" \
  develop "path:$project_root/nix" \
  -c "$@"
