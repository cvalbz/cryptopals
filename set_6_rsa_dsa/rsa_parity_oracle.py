import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from utils import random_integer, base64_to_bytearray
from implement_rsa import RSA, modinv, rsa_string_to_integer, rsa_integer_to_string
from decimal import *
from math import ceil, floor, log

ORACLE_KEY = RSA(1024, e=65537)
ORACLE_KEY.generate_keys()

def parity_oracle(ciphertext):
    plaintext_int = ORACLE_KEY.decrypt(ciphertext, encode=False)
    return plaintext_int % 2 == 0

def attack_parity_oracle(ciphertext, e, n):
    lb = Decimal(0)
    ub = Decimal(n)

    k = int(ceil(log(n, 2)))    # n. of iterations
    getcontext().prec = k       # allows for 'precise enough' floats

    c = ciphertext
    enctwo = pow(2, e, n)

    for i in xrange(1, k+1):
        c = (c * enctwo) % n
        nb = (lb + ub) / 2

        if parity_oracle(c):
            ub = nb
        else:
            lb = nb

        print "%s: %s" % (i, rsa_integer_to_string(int(ub)))

    return rsa_integer_to_string(int(ub))

def main():
    plaintext_b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    plaintext =  str(base64_to_bytearray(plaintext_b64))
    ciphertext = ORACLE_KEY.encrypt(plaintext)

    found_plaintext = attack_parity_oracle(ciphertext, ORACLE_KEY.e, ORACLE_KEY.N)

    if found_plaintext == plaintext:
        print("challenge 5.46 completed.")
    else:
        print("challenge 5.46 failed.")

if __name__ == "__main__":
    main()