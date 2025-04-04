#!/usr/bin/env python3
from Crypto.Util.number import *
from flag import FLAG as launch_codes
from Crypto.Cipher import AES
import random
import hashlib

#NIST standard right?
p = 12355965363681829030886858436940896808121432892809976808808113328111573544690718535585283264325149623107296321179415012746310836042877339545502235209822814113184844161176429333448787991914774445673708973884689913061003541404950691846319197056810795155849217
g = 2

#Alice
a = random.randint(0, p-1)
A = pow(g, a, p)
print('Hey Bob, my number A is', A)

#Bob
b = random.randint(0, p-1)
B = pow(g, b, p)
print('Hey Alice, my number B is', B)

#Alice
shared = pow(B, a, p)
shared_key = hashlib.md5(long_to_bytes(shared)).digest()
encrypted_launch_codes = AES.new(shared_key, AES.MODE_ECB).encrypt(launch_codes)
print("Ok, here is the nuclear launch codes encrypted with AES. I used our shared secret g^(a*b) as key: {}".format(encrypted_launch_codes.hex()))

#Bob
shared = pow(A, b, p)
shared_key = hashlib.md5(long_to_bytes(shared)).digest()
decrypted_launch_codes = AES.new(shared_key, AES.MODE_ECB).decrypt(encrypted_launch_codes)
print('Got it, I hope we will never have to use them')
