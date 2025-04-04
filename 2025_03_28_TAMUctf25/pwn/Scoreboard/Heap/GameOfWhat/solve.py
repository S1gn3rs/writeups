#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.27.so")

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





    r.interactive()

if __name__ == "__main__":
    main()