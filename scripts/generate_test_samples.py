# MAP — Synthetic Test Sample Generator
# Generates synthetic PE files and memory dumps for testing the analysis pipeline.

import os
import struct

def create_synthetic_pe(filename: str):
    """Create a minimal valid DOS/PE structure for basic testing."""
    
    # DOS Header
    dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x40)
    
    # DOS Stub
    dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
    dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
    dos_stub += b'\x00' * (0x40 - len(dos_header) - len(dos_stub))
    
    # PE Header
    pe_header = b'PE\x00\x00' + struct.pack('<H', 0x014C) # Machine (x86)
    pe_header += struct.pack('<H', 2) # NumberOfSections
    pe_header += struct.pack('<I', 0x5E8F1B3A) # TimeDateStamp
    pe_header += b'\x00' * 8 # PointerToSymbolTable, NumberOfSymbols
    pe_header += struct.pack('<H', 0x00E0) # SizeOfOptionalHeader
    pe_header += struct.pack('<H', 0x010F) # Characteristics
    
    # Optional Header
    opt_header = struct.pack('<H', 0x010B) # Magic (PE32)
    opt_header += b'\x00' * 14 # Linker, SizeOfCode, SizeOfInit/Uninit
    opt_header += struct.pack('<I', 0x1000) # AddressOfEntryPoint
    opt_header += b'\x00' * 4 # BaseOfCode
    opt_header += struct.pack('<I', 0x400000) # ImageBase
    opt_header += b'\x00' * 28 # Alignments, Versions, etc
    opt_header += struct.pack('<I', 0x2000) # SizeOfImage
    opt_header += struct.pack('<I', 0x200) # SizeOfHeaders
    opt_header += b'\x00' * 4 # Checksum
    opt_header += struct.pack('<H', 2) # Subsystem (GUI)
    opt_header += b'\x00' * 30 # DLL Characteristics, Stack/Heap sizes, etc
    opt_header += struct.pack('<I', 16) # NumberOfRvaAndSizes
    opt_header += b'\x00' * 128 # Data Directories
    
    # Sections
    section_text = b'.text\x00\x00\x00'
    section_text += struct.pack('<I', 0x1000) # VirtualSize
    section_text += struct.pack('<I', 0x1000) # VirtualAddress
    section_text += struct.pack('<I', 0x200) # SizeOfRawData
    section_text += struct.pack('<I', 0x200) # PointerToRawData
    section_text += b'\x00' * 12 # PointerToRelocations, etc
    section_text += struct.pack('<I', 0x60000020) # Characteristics (Code, Execute, Read)
    
    section_data = b'.data\x00\x00\x00'
    section_data += struct.pack('<I', 0x1000)
    section_data += struct.pack('<I', 0x2000)
    section_data += struct.pack('<I', 0x200)
    section_data += struct.pack('<I', 0x400)
    section_data += b'\x00' * 12
    section_data += struct.pack('<I', 0xC0000040) # Characteristics (InitData, Read, Write)
    
    # Payload / Strings
    text_data = b'\x90' * 0x100 # NOPs
    text_data += b'VirtualAlloc' + b'\x00' * 4
    text_data += b'WriteProcessMemory' + b'\x00' * 2
    text_data += b'\x00' * (0x200 - len(text_data))
    
    data_data = b'http://malicious-test-domain.com/payload.exe' + b'\x00' * 4
    data_data += b'C:\\Windows\\System32\\cmd.exe' + b'\x00' * 4
    data_data += b'192.168.100.50' + b'\x00' * 6
    data_data += b'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' + b'\x00'
    data_data += b'\x00' * (0x200 - len(data_data))
    
    # Write file
    with open(filename, 'wb') as f:
        f.write(dos_header)
        f.write(dos_stub)
        f.write(pe_header)
        f.write(opt_header)
        f.write(section_text)
        f.write(section_data)
        
        # Pad to raw data
        pad_size = 0x200 - f.tell()
        if pad_size > 0:
            f.write(b'\x00' * pad_size)
            
        f.write(text_data)
        f.write(data_data)

if __name__ == "__main__":
    os.makedirs("test_samples", exist_ok=True)
    
    pe_path = os.path.join("test_samples", "synthetic_malware.exe")
    create_synthetic_pe(pe_path)
    print(f"Created synthetic PE file at {pe_path}")
