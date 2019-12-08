import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from utils import random_integer
from implement_rsa import modinv
import hashlib

P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7"
        "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
        "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
        "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
        "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
        "1a584471bb1", 16)
 
Q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
 
G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
        "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
        "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
        "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
        "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
        "9fc95302291", 16)

class DSA_no_verify_params:
    def __init__(self, p=P, q=Q, g=G):
        self.p = p
        self.q = q
        self.g = g

    def generate_keys(self):
        self.x = random_integer(1, self.q-1)
        self.y = pow(self.g, self.x, self.p)

    def sign(self, message):
        h = int(hashlib.sha1(message).hexdigest(), 16)

        k = random_integer(2, self.q-1)
        r = pow(self.g, k, self.p) % self.q
        s = (modinv(k, self.q) * (h + self.x * r)) % self.q

        #if r == 0 or s == 0:
        #    return self.sign(message)

        return (r,s)

    def verify(self, signature, message):
        (r,s) = signature

        #if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
        #    return False

        w = modinv(s, self.q)

        h = int(hashlib.sha1(message).hexdigest(), 16)
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q

        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p ) % self.q

        return v == r

def forge_signature(y):
    z = random_integer(1, 2**16)
    r = pow(y, z, P) % Q
    s = (r * modinv(z, Q)) % Q

    return (r, s)

def main():
    signer = DSA_no_verify_params(p=P, q=Q, g=G)
    signer.generate_keys()

    message = 'SATOSHI NAKAMOTO'
    signature = signer.sign(message)
    assert signer.verify(signature, message)

    signer.g = 0
    assert signer.verify((0, 666), 'Alice')
    assert signer.verify((0, 1337), 'Bob')

    #####################################################

    signer = DSA_no_verify_params(p=P, q=Q, g=G)
    signer.generate_keys()

    message = 'SATOSHI NAKAMOTO'
    signature = signer.sign(message)
    assert signer.verify(signature, message)

    signer.g = P+1
    sig1 = signer.verify(forge_signature(signer.y), "Hello, world")
    sig2 = signer.verify(forge_signature(signer.y), "Goodbye, world")

    if sig1 and sig2:
        print("challenge 5.45 completed.")
    else:
        print("challenge 5.45 failed.")

if __name__ == "__main__":
    main()