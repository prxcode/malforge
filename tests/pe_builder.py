"""Build a small, harmless PE file for tests.

The file is structurally valid enough for pefile to parse, but it has no
import table and its code section is NOPs, so it does nothing if executed.

Run directly to write a sample for trying the CLI by hand:

    python tests/pe_builder.py sample.exe
"""

import struct
import sys
from pathlib import Path

FILE_ALIGNMENT = 0x200

TEXT_STRINGS = (b"VirtualAllocEx", b"WriteProcessMemory")
DATA_STRINGS = (
    b"http://malicious-test-domain.com/payload.exe",
    b"C:\\Windows\\System32\\cmd.exe",
    b"203.0.113.50",
    b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
)


def _section_header(name: bytes, rva: int, raw_offset: int, characteristics: int) -> bytes:
    return (
        name.ljust(8, b"\x00")
        + struct.pack("<IIII", 0x1000, rva, FILE_ALIGNMENT, raw_offset)
        + b"\x00" * 12
        + struct.pack("<I", characteristics)
    )


def _section_body(prefix: bytes, strings: tuple[bytes, ...]) -> bytes:
    body = prefix + b"".join(s + b"\x00" * 4 for s in strings)
    return body.ljust(FILE_ALIGNMENT, b"\x00")


def build_pe() -> bytes:
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub = dos_stub.ljust(64, b"\x00")

    file_header = b"PE\x00\x00" + struct.pack(
        "<HHIIIHH",
        0x014C,  # i386
        2,  # sections
        0x5E8F1B3A,  # timestamp
        0,
        0,
        0xE0,  # size of optional header
        0x010F,  # characteristics
    )

    optional_header = (
        struct.pack("<H", 0x010B)  # PE32
        + b"\x00" * 14
        + struct.pack("<I", 0x1000)  # entry point
        + b"\x00" * 8
        + struct.pack("<I", 0x400000)  # image base
        + b"\x00" * 24
        + struct.pack("<II", 0x3000, FILE_ALIGNMENT)  # size of image, size of headers
        + b"\x00" * 4
        + struct.pack("<H", 2)  # GUI subsystem
        + b"\x00" * 22
        + struct.pack("<I", 16)  # data directory count
        + b"\x00" * 128
    )

    headers = (
        dos_header
        + dos_stub
        + file_header
        + optional_header
        + _section_header(b".text", 0x1000, FILE_ALIGNMENT, 0x60000020)
        + _section_header(b".data", 0x2000, FILE_ALIGNMENT * 2, 0xC0000040)
    ).ljust(FILE_ALIGNMENT, b"\x00")

    return headers + _section_body(b"\x90" * 0x100, TEXT_STRINGS) + _section_body(b"", DATA_STRINGS)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "sample.exe")
    out.write_bytes(build_pe())
    print(f"Wrote {out}")
