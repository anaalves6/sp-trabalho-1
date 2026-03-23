#key generator

from cryptography.hazmat.primitives.asymmetric import rsa

def key_generator():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    numbers = private_key.private_numbers()

    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d

    return (n,e,d)

#evaluation e inversion

def rsa_eval(x,e,n):
    return pow(x,e,n)

def rsa_inv(x,d,n):
    return pow(x,d,n)

#SH256

import hashlib

def H(i,r):

    data = i.to_bytes(4,'big') + r.to_bytes(32,'big')

    return hashlib.sha256(data).digest()

#xor

def xor_bytes(a,b):

    return bytes(x^y for x,y in zip(a,b))

#encryption (raw)

import os
import math

def encrypt(m,n,e):

    l = 32
    r = int.from_bytes(os.urandom(32),'big')

    c0 = rsa_eval(r,e,n)

    blocks = [m[i:i+l] for i in range(0,len(m),l)]

    ciphertext_blocks = []

    for i,block in enumerate(blocks):

        h = H(i,r)

        ciphertext_blocks.append(
            xor_bytes(block, h[:len(block)])
        )

    return (c0, ciphertext_blocks)

#decryption

def decrypt(c0, blocks, n, d):

    r = rsa_inv(c0,d,n)

    message = b''

    for i,block in enumerate(blocks):

        h = H(i,r)

        message += xor_bytes(block, h[:len(block)])

    return message

#tempo

import time
import statistics

sizes = [8,64,512,4096,32768,262144,2097152]

n,e,d = key_generator()

for s in sizes:

    with open(f"ficheiro_{s}.txt","rb") as f:
        data = f.read()

    enc_times=[]
    dec_times=[]

    for _ in range(20):

        start=time.perf_counter()
        c0,c=encrypt(data,n,e)
        enc_times.append(time.perf_counter()-start)

        start=time.perf_counter()
        decrypt(c0,c,n,d)
        dec_times.append(time.perf_counter()-start)

    print(
        s,
        statistics.mean(enc_times)*1e6,
        statistics.mean(dec_times)*1e6
    )