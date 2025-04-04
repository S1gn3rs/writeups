from pwn import *
import numpy as np
from sympy import Matrix

P = remote("mustard.stt.rnl.tecnico.ulisboa.pt", 11102)

# Finding a polinomial When Given Points

storeValues = {}

def getNumber(num):
    P.sendlineafter(b">>", b"1")
    P.sendlineafter(b">>", str(num).encode())
    P.recvuntil(b"P[")
    P.recvuntil(b"=")
    return int(P.recvline().strip())

def getPossNumbers(target):
    storeValues[target + 1] = getNumber(target + 1)
    storeValues[target - 1] = getNumber(target - 1)


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
    # output = P.recv(timeout=1)
    if output == b"":
        print("No output")

    print(output)
    if b"Incorrect!" in output:
        return False

    print(output)
    return True







P.recvuntil(b"2. Guess P[")
number = int(P.recvuntil(b"]")[:-1])
log.success(f"This is the number: {number}")




getPossNumbers(number)
poll = getPolynomial()

print("This is the base guess", poll[-1])

if (gessNumber(poll[-1])): log.success("Got it! 0")

for i in range(1, 3):
    if gessNumber(poll[-1] + i): log.success(f"Got it! {i}")
    if gessNumber(poll[-1] - i): log.success(f"Got it! {-i}")


P.interactive()
