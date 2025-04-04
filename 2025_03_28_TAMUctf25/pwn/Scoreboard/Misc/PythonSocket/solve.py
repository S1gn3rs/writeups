from pwn import *

P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 15001)


P.recvuntil(b"l you get to ")
objective = int(P.recvline()[:-2])


def finish():
    P.sendlineafter(b"- A number (type MORE)?\n- Or are you done (type FINISH)?", b"FINISH")

def sendValue():
    P.sendlineafter(b"- A number (type MORE)?\n- Or are you done (type FINISH)?", b"MORE")

def getCurret():
    P.recvuntil(b"CURRENT = ")
    return int(P.recvline()[:-2])


while getCurret() != objective:
    sendValue()

finish()

# GOT

P.interactive()