from pwn import *
import numpy as np
from sympy import Matrix

P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 11101)

# Finding a polinomial When Given Points

storeValues = {}

def getNumber(num):
    P.sendlineafter(b">>", b"1")
    P.sendlineafter(b">>", str(num).encode())
    P.recvuntil(b"P[")
    P.recvuntil(b"=")
    return int(P.recvline().strip())

def getPossNumbers(num):
    div = num // 2
    for i in range(1, div + 1):
        storeValues[i] = getNumber(i)
        storeValues[-i] = getNumber(-i)
    if num % 2 == 1:
        storeValues[div + 1] = getNumber(div + 1)



def getPolynomial():
    x_values = sorted(storeValues.keys())  # Sorted x-values
    y_values = [storeValues[x] for x in x_values]  # Corresponding y-values

    # Construct Vandermonde matrix using x-values
    matrix = Matrix([[x**j for j in range(len(x_values) - 1, -1, -1)] for x in x_values])
    vector = Matrix(y_values)

    # Solve using exact arithmetic
    poll = matrix.LUsolve(vector)
    return [int(p) for p in poll]  # Convert to integer





def gessNumber(num):
    P.sendlineafter(b">>", b"2")
    print("Number to send:", str(num).encode())
    P.sendlineafter(b">>", str(num).encode())

    output = P.recvuntil(b"Incorrect!", timeout=3)
    output = P.recv(timeout=1)

    print(output)
    if b"Incorrect!" in output:
        return False

    print(output)
    return True





P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 11101)

getPossNumbers(30)
poll = getPolynomial()

print((poll[-1]))
gessNumber(poll[-1])
P.interactive()
