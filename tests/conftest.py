

import os
import struct

import pytest


@pytest.fixture
def synthetic_pe_data() -> bytes:
    """Create a minimal valid PE with suspicious strings baked in."""
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

    # DOS Stub
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub += b"\x00" * (64 - len(dos_stub))

    # PE Header
    pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C)  # Machine (x86)
    pe_header += struct.pack("<H", 2)  # NumberOfSections
    pe_header += struct.pack("<I", 0x5E8F1B3A)  # TimeDateStamp
    pe_header += b"\x00" * 8  # PointerToSymbolTable, NumberOfSymbols
    pe_header += struct.pack("<H", 0x00E0)  # SizeOfOptionalHeader
    pe_header += struct.pack("<H", 0x010F)  # Characteristics

    # Optional Header (Exactly 224 bytes / 0xE0)
    opt_header = struct.pack("<H", 0x010B)  # Magic (PE32) (2)
    opt_header += b"\x00" * 14  # Linker/Size data (14) -> Offset 16
    opt_header += struct.pack("<I", 0x1000)  # AddressOfEntryPoint (4) -> Offset 20
    opt_header += b"\x00" * 8  # BaseOfCode, BaseOfData (8) -> Offset 28
    opt_header += struct.pack("<I", 0x400000)  # ImageBase (4) -> Offset 32
    opt_header += b"\x00" * 24  # Alignments, OS versions, etc (24) -> Offset 56
    opt_header += struct.pack("<I", 0x2000)  # SizeOfImage (4) -> Offset 60
    opt_header += struct.pack("<I", 0x200)  # SizeOfHeaders (4) -> Offset 64
    opt_header += b"\x00" * 4  # CheckSum (4) -> Offset 68
    opt_header += struct.pack("<H", 2)  # Subsystem (GUI) (2) -> Offset 70
    opt_header += b"\x00" * 22  # DllChars, Stack/Heap sizes (22) -> Offset 92
    opt_header += struct.pack("<I", 16)  # NumberOfRvaAndSizes (4) -> Offset 96
    opt_header += b"\x00" * 128  # Data Directories (128) -> Offset 224

    # Sections
    section_text = b".text\x00\x00\x00"
    section_text += struct.pack("<I", 0x1000)
    section_text += struct.pack("<I", 0x1000)
    section_text += struct.pack("<I", 0x200)
    section_text += struct.pack("<I", 0x200)
    section_text += b"\x00" * 12
    section_text += struct.pack("<I", 0x60000020)

    section_data = b".data\x00\x00\x00"
    section_data += struct.pack("<I", 0x1000)
    section_data += struct.pack("<I", 0x2000)
    section_data += struct.pack("<I", 0x200)
    section_data += struct.pack("<I", 0x400)
    section_data += b"\x00" * 12
    section_data += struct.pack("<I", 0xC0000040)

    # Text section data with suspicious strings
    text_data = b"\x90" * 0x100  # NOPs
    text_data += b"VirtualAlloc" + b"\x00" * 4
    text_data += b"WriteProcessMemory" + b"\x00" * 2
    text_data += b"\x00" * (0x200 - len(text_data))

    # Data section with IOC strings
    data_data = b"http://malicious-test-domain.com/payload.exe" + b"\x00" * 4
    data_data += b"C:\\Windows\\System32\\cmd.exe" + b"\x00" * 4
    data_data += b"192.168.100.50" + b"\x00" * 6
    data_data += b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" + b"\x00"
    data_data += b"\x00" * (0x200 - len(data_data))

    # Assemble
    full_header = dos_header + dos_stub + pe_header + opt_header + section_text + section_data
    pad_size = 0x200 - len(full_header)
    if pad_size > 0:
        full_header += b"\x00" * pad_size

    return full_header + text_data + data_data


@pytest.fixture
def synthetic_pe_file(synthetic_pe_data: bytes, tmp_path: "os.PathLike[str]") -> "os.PathLike[str]":
    """Write synthetic PE data to a temporary file."""
    pe_path = tmp_path / "test_sample.exe"
    pe_path.write_bytes(synthetic_pe_data)
    return pe_path
