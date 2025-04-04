TEMU 2025 - debug2 Writeup 🩸FIRST BLOOD🩸
========================================

Author: s1gn3rs
Team: STT
Date: March 28, 2025
GitHub: https://github.com/S1gn3rs/writeups/tree/502e91172c163ca588e4814cd8cc4a0525548bf7/2025_03_28_TAMUctf25/pwn/debug2

--------------------------------------------------------------------------------
Challenge Information
--------------------------------------------------------------------------------

Category: PWN
Challenge Name: debug2

Description:
    My friends gave me some advice to fix my code because apparently there were "glaring
    security flaws". Not sure what they meant, but now my code is more secure than ever!

--------------------------------------------------------------------------------
TL;DR
--------------------------------------------------------------------------------

Required:
    - Basic binary exploitation: Understand buffer overflows, stack frames, and memory layout.

Covered:
    - Stack pivoting: Redirect the stack pointer (RSP) to a controlled region.
    - ROP chain + one_gadget and ropper usage: Build ROP chains to leak addresses and execute payloads.

--------------------------------------------------------------------------------
Binary Security Features
--------------------------------------------------------------------------------

When analyzing a C binary, the first step is to check its permissions.

Command:
    $ checkec debug-2

Output:
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

--------------------------------------------------------------------------------
Key Observations
--------------------------------------------------------------------------------

    * Full RELRO prevents overwriting GOT entries.
    * PIE enabled: A memory leak is required to obtain correct addresses.
    * No canary: The stack is vulnerable to direct overwrites.
    * NX enabled: Execution of shellcode on the stack is prevented.

--------------------------------------------------------------------------------
Binary Analysis
--------------------------------------------------------------------------------

Functions Overview:
-------------------
1. upkeep:
   - Initializes standard I/O buffering.
2. main:
   - Calls upkeep.
   - Prints version and author strings.
   - Invokes menu and then prints an exit message.
3. menu:
   - Declares an integer "sel" and a character array "input" of length 69.
   - Loops until a valid option is chosen.
   - Option 1 calls modify, prints the modified string, then returns to main.
   - Option 2 (Debug Mode) prints a message that debug mode is disabled.
   - Option 3 exits.
4. modify:
   - Reads up to 96 bytes into a 69-byte buffer (introducing a buffer overflow vulnerability).
   - Immediately prints the input (leaking data) before performing a case-swap on each character.
   - The function converts lowercase letters to uppercase and vice versa.

--------------------------------------------------------------------------------
Exploitation Strategy
--------------------------------------------------------------------------------

1. Buffer Overflow:
   - The modify function reads 96 bytes into a 69-byte buffer.
   - Overwriting occurs in the caller’s (menu) stack frame, meaning the saved RIP in menu is overwritten.

2. Saved RIP Leak and Address Calculation:
   - The saved RIP offset was determined to be 0x58 bytes.
   - An extra byte (0xdd) is used to jump back to a known location in main, which leaks the saved RIP.
   - With the leak of main’s address, the base address of the binary is computed.

3. Stack Pivoting:
   - Since the input buffer (and hence overflow) is subject to a case-swap function, a helper function “convert_case” is implemented.
   - Stack pivoting is used to move the stack from its original location to the BSS, where a controlled payload is stored.
   - Overwrite the saved RBP with an address in the BSS and adjust the return address to jump to menu (after its prologue) to allow further input.

4. Libc Leak via ROP Chain:
   - A ROP chain is built using gadgets obtained with ropper.
   - A “pop rdi; ret;” gadget is used to call puts with the GOT entry of puts itself as an argument.
   - This leak of puts’ address allows calculation of the libc base address.
   - The chain then returns to menu so that further exploitation can occur.

5. Final Payload and One-Gadget:
   - Once libc is leaked, a final payload is constructed to overwrite the saved RIP.
   - Instead of a full ROP chain, a one_gadget (from one_gadget tool) is used.
   - Conditions for the one_gadget are met by ensuring proper stack alignment.
   - The final payload overwrites the saved RIP with the one_gadget address, thus spawning a shell.

--------------------------------------------------------------------------------
Exploit Code Summary
--------------------------------------------------------------------------------

The exploit consists of three stages:
    1. Leak the saved RIP and compute the base address of the binary.
    2. Stack pivoting to move the stack to the BSS.
    3. Building a ROP chain to leak libc’s address and compute its base, followed by
       overwriting the return address with a one_gadget that spawns a shell.

The provided Python exploit uses pwntools to:
    - Communicate with the process.
    - Send carefully crafted payloads that account for the case conversion.
    - Leak addresses and compute offsets.
    - Execute the final payload to get a shell.

--------------------------------------------------------------------------------
Flag
--------------------------------------------------------------------------------

gigem{f1x3d_d3buG6iN_y3t_st1Ll_f1aWeD_3da42ce3}

--------------------------------------------------------------------------------
Notes
--------------------------------------------------------------------------------

This writeup details the methodology and process used in the debug2 challenge.
Key techniques include:
    - Buffer overflow exploitation.
    - Stack pivoting.
    - Return Oriented Programming (ROP).
    - Libc address leak and one_gadget usage.

