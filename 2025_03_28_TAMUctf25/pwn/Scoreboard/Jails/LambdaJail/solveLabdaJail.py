from pwn import *

P = process("mustard.stt.rnl.tecnico.ulisboa.pt", 11001)
P.send(b"bla")
P.interactive()