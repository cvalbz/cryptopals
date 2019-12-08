"""
  Classic RSA broadcast attack.
  http://www.di-mgt.com.au/crt.html
"""

import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
from implement_rsa import RSA, modinv, rsa_integer_to_string
import sympy

def encrypt_broadcast_message(message):
    rsa = RSA(2048, e=3)
    rsa.generate_keys()

    return rsa.encrypt(message), rsa.N

def main():
    message = "SATOSHI NAKAMOTO"

    c1, n1 = encrypt_broadcast_message(message)
    c2, n2 = encrypt_broadcast_message(message)
    c3, n3 = encrypt_broadcast_message(message)

    N = n1 * n2 * n3

    N1 = N // n1
    N2 = N // n2
    N3 = N // n3

    d1 = modinv(N1, n1)
    d2 = modinv(N2, n2)
    d3 = modinv(N3, n3)

    x = (c1*N1*d1 + c2*N2*d2 + c3*N3*d3) % N

    m = sympy.integer_nthroot(x, 3)[0]
    message_decrypted = rsa_integer_to_string(m)

    if message_decrypted == message:
        print("challenge 5.40 completed.")
    else:
        print("challenge 5.40 failed.")

if __name__ == "__main__":
    main()