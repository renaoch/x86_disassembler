Overview

This project is a simple x86 disassembler written in Python. It reads raw machine code from a binary file and dynamically decodes opcodes, ModRM bytes, and register/memory addressing to generate human-readable assembly instructions.

Features

Reads raw x86 machine code from .bin, .elf, or .exe files.

Decodes common instructions like MOV, INC, and multi-byte opcodes.

Parses ModRM bytes to determine registers and memory operands.

Extracts and disassembles the .text section of ELF (Linux) and PE (Windows) executables.

CLI-based interface for easy usage.

Installation

Requirements

Python 3.x

No additional dependencies required

Clone Repository

git clone https://github.com/renaoch/x86-disassembler.git
cd x86-disassembler

Usage

Disassembling a Raw Binary File

python disassembler.py code.bin

Disassembling an ELF Executable

python disassembler.py program.elf

Disassembling a Windows EXE

python disassembler.py program.exe

Example Output

Input (code.bin):

B8 05 00 00 00 89 D8

Output:

MOV EAX, 5
MOV EBX, EAX

How It Works

Reads raw bytes from the given file.

Identifies opcodes dynamically (single/multi-byte).

Extracts ModRM and register/memory operands.

Prints the corresponding assembly instructions.

Future Improvements

Support for more complex x86 instructions.

Improved ELF/PE parsing for accurate section extraction.

Enhanced CLI with better formatting and additional options.

License

This project is licensed under the MIT License.
