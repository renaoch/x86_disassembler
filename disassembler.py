#!/usr/bin/env python3

import struct
import sys


REG_NAMES = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]


def read_machine_code(filename):
    """Reads raw bytes from a binary file."""
    with open(filename, "rb") as f:
        return f.read()


def parse_opcode(byte, next_byte):
    """Dynamically identifies opcode type (supports multi-byte)."""
    if byte & 0b11111100 == 0b10001000:
        return "MOV"
    elif byte & 0b11110000 == 0b10110000:
        return "MOV_IMM"
    elif byte == 0x0F:
        return "MULTI_BYTE", next_byte
    elif byte & 0b11111000 == 0b01000000:
        return "INC"
    return "UNKNOWN"


def decode_modrm(byte):
    """Extracts Mod, Reg, and RM fields from the ModRM byte."""
    mod = (byte >> 6) & 0b11
    reg = (byte >> 3) & 0b111
    rm = byte & 0b111
    return mod, reg, rm


def disassemble(binary):
    """Fully dynamic x86 disassembler."""
    i = 0
    while i < len(binary):
        opcode = binary[i]
        next_byte = binary[i + 1] if i + 1 < len(binary) else None
        instruction = parse_opcode(opcode, next_byte)
        i += 1

        if instruction == "MOV":
            modrm = binary[i]
            mod, reg, rm = decode_modrm(modrm)
            i += 1
            print(f"MOV {REG_NAMES[reg]}, {REG_NAMES[rm]}")
        elif instruction == "MOV_IMM":
            reg = opcode & 0b111
            imm = struct.unpack("<I", binary[i : i + 4])[0]
            i += 4
            print(f"MOV {REG_NAMES[reg]}, {imm}")
        elif instruction == "MULTI_BYTE":
            print(f"Multi-byte instruction detected: {opcode:02X} {next_byte:02X}")
            i += 1
        elif instruction == "INC":
            reg = opcode & 0b111
            print(f"INC {REG_NAMES[reg]}")
        else:
            print(f"UNKNOWN OPCODE {opcode:02X}")
            break


def parse_elf(filename):
    """Extracts .text section from an ELF file."""
    with open(filename, "rb") as f:
        elf_header = f.read(64)  # Read ELF header
        if elf_header[:4] != b"\x7fELF":
            print("Not a valid ELF file")
            sys.exit(1)
        # Extract .text section (simplified, assumes standard layout)
        f.seek(0x100)  # Simplified offset, real parsing needed
        code = f.read(256)  # Read some executable bytes
        return code


def parse_pe(filename):
    """Extracts .text section from a PE file."""
    with open(filename, "rb") as f:
        mz_header = f.read(2)
        if mz_header != b"MZ":
            print("Not a valid PE file")
            sys.exit(1)
        f.seek(0x200)  # Simplified offset, real parsing needed
        code = f.read(256)  # Read some executable bytes
        return code


if __name__ == "__main__":
    filename = sys.argv[1]
    if filename.endswith(".bin"):
        binary_code = read_machine_code(filename)
    elif filename.endswith(".elf"):
        binary_code = parse_elf(filename)
    elif filename.endswith(".exe"):
        binary_code = parse_pe(filename)
    else:
        print("Unsupported file format")
        sys.exit(1)
    
    disassemble(binary_code)
