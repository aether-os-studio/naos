#!/usr/bin/env python3
"""Append a NAOS ECDSA P-256 module signature.

Usage:
  python3 kernel/scripts/sign_module.py <module_file> <private_key.pem>

The appended footer matches kernel/src/mod/modchk.h:
  uint32_t magic      little-endian NAOS_SIG_MAGIC
  uint8_t  hash_algo  1 = SHA256
  uint8_t  sig_len    64
  uint8_t  reserved[2]
  uint8_t  signature  ECDSA R || S, 32-byte big-endian integers
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


NAOS_SIG_MAGIC = 0x4E414F53
HASH_SHA256 = 1
ECC_SIG_LEN = 64
SIG_HEADER = struct.Struct("<IBB2s")
SIG_TOTAL_LEN = SIG_HEADER.size + ECC_SIG_LEN


class SignError(RuntimeError):
    pass


def _read_der_len(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise SignError("truncated DER length")

    first = data[off]
    off += 1
    if first < 0x80:
        return first, off

    count = first & 0x7F
    if count == 0 or count > 4:
        raise SignError("unsupported DER length")
    if off + count > len(data):
        raise SignError("truncated DER long length")

    length = int.from_bytes(data[off : off + count], "big")
    off += count
    return length, off


def _read_der_integer(data: bytes, off: int) -> tuple[bytes, int]:
    if off >= len(data) or data[off] != 0x02:
        raise SignError("expected DER INTEGER")
    off += 1

    length, off = _read_der_len(data, off)
    end = off + length
    if end > len(data):
        raise SignError("truncated DER INTEGER")

    raw = data[off:end].lstrip(b"\x00")
    if len(raw) > 32:
        raise SignError("ECDSA integer is wider than P-256")

    return raw.rjust(32, b"\x00"), end


def der_ecdsa_to_raw_rs(der: bytes) -> bytes:
    if not der or der[0] != 0x30:
        raise SignError("expected DER SEQUENCE")

    seq_len, off = _read_der_len(der, 1)
    seq_end = off + seq_len
    if seq_end != len(der):
        raise SignError("invalid DER SEQUENCE length")

    r, off = _read_der_integer(der, off)
    s, off = _read_der_integer(der, off)
    if off != seq_end:
        raise SignError("trailing bytes in DER signature")

    return r + s


def strip_existing_signature(module_path: Path) -> bool:
    size = module_path.stat().st_size
    if size < SIG_TOTAL_LEN:
        return False

    with module_path.open("rb") as f:
        f.seek(size - SIG_TOTAL_LEN)
        footer = f.read(SIG_TOTAL_LEN)

    magic, hash_algo, sig_len, _reserved = SIG_HEADER.unpack(
        footer[: SIG_HEADER.size]
    )
    if magic != NAOS_SIG_MAGIC or hash_algo != HASH_SHA256 or sig_len != ECC_SIG_LEN:
        return False

    with module_path.open("rb+") as f:
        f.truncate(size - SIG_TOTAL_LEN)
    return True


def sign_module(module_path: Path, private_key: Path) -> None:
    if not module_path.is_file():
        raise SignError(f"module file not found: {module_path}")
    if not private_key.is_file():
        raise SignError(f"private key not found: {private_key}")

    if strip_existing_signature(module_path):
        print(f"[MODULE-SIGN] stripped existing signature: {module_path}")

    with tempfile.TemporaryDirectory(prefix="naos-module-sign.") as tmpdir:
        der_sig = Path(tmpdir) / "signature.der"
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                os.fspath(private_key),
                "-out",
                os.fspath(der_sig),
                os.fspath(module_path),
            ],
            check=True,
        )
        raw_sig = der_ecdsa_to_raw_rs(der_sig.read_bytes())

    footer = SIG_HEADER.pack(NAOS_SIG_MAGIC, HASH_SHA256, ECC_SIG_LEN, b"\x00\x00")
    with module_path.open("ab") as f:
        f.write(footer)
        f.write(raw_sig)

    print(f"[MODULE-SIGN] signed: {module_path}")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "Usage: python3 kernel/scripts/sign_module.py <module_file> <private_key.pem>",
            file=sys.stderr,
        )
        return 1

    try:
        sign_module(Path(argv[1]), Path(argv[2]))
    except subprocess.CalledProcessError as exc:
        print(f"Error: openssl failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode or 1
    except (OSError, SignError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
