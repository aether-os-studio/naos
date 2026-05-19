#!/usr/bin/env sh
# Generate or refresh the ECC key material used for module signature checking.
#
# Usage:
#   sh kernel/scripts/gen_module_signing_keys.sh [key_dir] [array_name]
#
# Outputs:
#   <key_dir>/module_signing_priv.pem
#   <key_dir>/module_signing_pub.pem
#   <key_dir>/pubkey.h

set -eu

KEY_DIR=${1:-kernel/obj-${ARCH:-x86_64}/module-signing}
ARRAY_NAME=${2:-naos_signing_key_pub}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PRIV_KEY=$KEY_DIR/module_signing_priv.pem
PUB_KEY=$KEY_DIR/module_signing_pub.pem
PUB_HEADER=$KEY_DIR/pubkey.h
TMP_PUB=$(mktemp "${TMPDIR:-/tmp}/naos-module-pub.XXXXXX")
TMP_HEADER=$(mktemp "${TMPDIR:-/tmp}/naos-module-pubkey.XXXXXX")
trap 'rm -f "$TMP_PUB" "$TMP_HEADER"' EXIT INT TERM

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl command not found." >&2
    exit 1
fi

mkdir -p "$KEY_DIR"

if [ ! -f "$PRIV_KEY" ]; then
    echo "[MODULE-SIGN] generating P-256 private key: $PRIV_KEY"
    umask 077
    openssl ecparam -name prime256v1 -genkey -noout -out "$PRIV_KEY"
    chmod 0600 "$PRIV_KEY"
else
    echo "[MODULE-SIGN] using existing private key: $PRIV_KEY"
fi

echo "[MODULE-SIGN] exporting public key: $PUB_KEY"
openssl ec -in "$PRIV_KEY" -pubout -out "$TMP_PUB" >/dev/null 2>&1
if [ ! -f "$PUB_KEY" ] || ! cmp -s "$TMP_PUB" "$PUB_KEY"; then
    cp "$TMP_PUB" "$PUB_KEY"
fi
chmod 0644 "$PUB_KEY"

echo "[MODULE-SIGN] generating public key header: $PUB_HEADER"
sh "$SCRIPT_DIR/convert_ecc_pubkey.sh" "$PUB_KEY" "$TMP_HEADER" "$ARRAY_NAME" >/dev/null
if [ ! -f "$PUB_HEADER" ] || ! cmp -s "$TMP_HEADER" "$PUB_HEADER"; then
    cp "$TMP_HEADER" "$PUB_HEADER"
fi
chmod 0644 "$PUB_HEADER"

echo "[MODULE-SIGN] done"
