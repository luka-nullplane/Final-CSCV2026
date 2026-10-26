#!/usr/bin/env python3
"""Solve the CSCV2026 `gdb` verifier by reversing its byte transform.

Usage:
    python3 solve.py path/to/gdb

Only Python's standard library is required. The file is never executed.
"""

import argparse
import hashlib
from pathlib import Path


# File offsets recovered from the stripped x86-64 ELF.
TEXT_OFFSET = 0xB0
TEXT_SIZE = 0x7E6
EXPECTED_OFFSET = 0x1000
FLAG_LENGTH = 0x3E


def ror8(value: int, shift: int) -> int:
    shift &= 7
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def rol8(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def solve(binary: bytes) -> bytes:
    if not binary.startswith(b"\x7fELF"):
        raise ValueError("Input does not look like an ELF binary")
    if len(binary) < max(TEXT_OFFSET + TEXT_SIZE, EXPECTED_OFFSET + FLAG_LENGTH):
        raise ValueError("Binary is too small for the expected offsets")

    # SIGTRAP handler computes SHA256(.text) into a 32-byte key buffer.
    key = hashlib.sha256(binary[TEXT_OFFSET:TEXT_OFFSET + TEXT_SIZE]).digest()
    expected = binary[EXPECTED_OFFSET:EXPECTED_OFFSET + FLAG_LENGTH]

    # Forward verifier:
    #   expected[i] == ROL8(((flag[i] + previous) & 255) ^ key[i % 32], i % 8)
    #   previous = flag[i] (previous starts at 0)
    flag = bytearray()
    previous = 0
    for i, target in enumerate(expected):
        unrotated = ror8(target, i % 8)
        current = ((unrotated ^ key[i % 32]) - previous) & 0xFF
        flag.append(current)
        previous = current

    # Re-run the transform locally to catch extraction/implementation errors.
    previous = 0
    for i, current in enumerate(flag):
        transformed = rol8((((current + previous) & 0xFF) ^ key[i % 32]), i % 8)
        assert transformed == expected[i], f"Verifier mismatch at index {i}"
        previous = current

    return bytes(flag)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=Path("gdb"),
                        help="Path to the challenge ELF (default: ./gdb)")
    args = parser.parse_args()
    flag = solve(args.binary.read_bytes())
    print(flag.decode("ascii"))


if __name__ == "__main__":
    main()
