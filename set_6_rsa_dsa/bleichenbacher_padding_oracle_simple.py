import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from utils import crypto_non_zero_random_bytes, random_integer
from implement_rsa import RSA, modinv
import binascii
from random import randrange, getrandbits
from itertools import repeat
import time

def bytes_to_integer(bt):
    return int(str(bt).encode('hex'), 16)

def integer_to_bytes(i, size):
    hex_string = '%x' % i
    n = len(hex_string)
    bt = binascii.unhexlify(hex_string.zfill(n + (n & 1)))

    bt = '\x00'*(size-len(bt)) + bt
    return bytearray(bt)

def getPrime(n):
    """Get a n-bit pseudo-random prime"""
    def isProbablePrime(n, t = 7):
        """Miller-Rabin primality test"""
        def isComposite(a):
            """Check if n is composite"""
            if pow(a, d, n) == 1:
                return False
            for i in range(s):
                if pow(a, 2 ** i * d, n) == n - 1:
                    return False
            return True
     
        assert n > 0
        if n < 3:
            return [False, False, True][n]
        elif not n & 1:
            return False
        else:
            s, d = 0, n - 1
            while not d & 1:
                s += 1
                d >>= 1
        for _ in repeat(None, t):
            if isComposite(randrange(2, n)):
                return False
        return True   
     
    p = getrandbits(n)
    while not isProbablePrime(p):
        p = getrandbits(n)
    return p

class RSA_PKCS_1_5:
    def __init__(self, s, e=65537):
        self.key = RSA(s, e=e)
        self.key.generate_keys() # replace RSA params

        
        self.key.p = getPrime(128)
        self.key.q = getPrime(128)
        self.key.N = self.key.p * self.key.q

        self.key.et = (self.key.p - 1) * (self.key.q - 1)

        self.key.d = modinv(self.key.e, self.key.et)
        assert self.key.d is not None, 'modinv failed'

        self.key.public_key = (self.key.N, self.key.e)
        self.key.private_key = (self.key.N, self.key.d)
        

        #self.key_length_bytes = s / 8
        self.key_length_bytes = (len(bin(self.key.N)[2:-1]) + 7) / 8

    def pad_pkcs(self, message):
        padding_string_length = self.key_length_bytes - 3 - len(message)
        padding_string = crypto_non_zero_random_bytes(padding_string_length)
        padded = bytearray([0, 2]) + padding_string + bytearray([0]) + bytearray(message)

        assert len(padded) == self.key_length_bytes, 'padding failed'
        return padded

    def unpad_pkcd(self, message):
        assert len(message) == self.key_length_bytes, 'cannot begin unpadding'
        #print list(message)

        if message[0] != 0 or message[1] != 2:
            raise Exception('invalid pkcs#1 padding')

        i = 2
        while message[i] != 0:
            i += 1

        return message[i+1:]

    def encrypt(self, message):
        padded = self.pad_pkcs(message)
        i = bytes_to_integer(padded)

        return self.key.encrypt(i, encode=False)

    def decrypt(self, ciphertext):
        m_int = self.key.decrypt(ciphertext, encode=False)
        m = integer_to_bytes(m_int, self.key_length_bytes)
        unpadded = self.unpad_pkcd(m)

        return unpadded

    def encrypt_no_pkcs(self, message):
        i = bytes_to_integer(message)
        return self.key.encrypt(i, encode=False)

    def decrypt_no_pkcs(self, ciphertext):
        m_int = self.key.decrypt(ciphertext, encode=False)
        m = integer_to_bytes(m_int, self.key_length_bytes)
        
        return m

def padding_oracle(key, ciphertext_int):
    try:
        message = key.decrypt(ciphertext_int)
        return True
    except Exception as e:
        if e.args[0] == 'invalid pkcs#1 padding':
            return False

def step_2a_starting_the_search(rsa, B, c0):
    s1 = (rsa.key.N + 3 * B - 1) / (3*B)

    while True:
        crafted_c = (c0 * pow(s1, rsa.key.e, rsa.key.N)) % rsa.key.N
        if padding_oracle(rsa, crafted_c):
            return s1
        s1 += 1
        print "trying s1 values in phase 2a: %s" % s1

def step_2c_search_one_interval(rsa, B, M, c0, S):
    if len(M) > 1:
        raise Exception('no multiple ranges')

    n = rsa.key.N
    a, b = M[0]

    r_low = (2 * (b * S - 2 * B)  + n - 1) / n
    r = r_low

    while True:   
        s_low = (2 * B + r * n + b - 1) / b
        s_high = (3 * B + r * n + a - 1) / a

        for s in range(s_low, s_high):
            crafted_c = (c0 * pow(s, rsa.key.e, n)) % n
            if padding_oracle(rsa, crafted_c):
                return s

        r += 1
        print "trying r values in phase 2c: %s" % r

def step_3_narrowing_the_set_of_solutions(rsa, B, M, S):
    if len(M) > 1:
        raise Exception('no multiple ranges')

    n = rsa.key.N
    a, b = M[0]
    si = S

    low_r = (a * si - 3 * B + 1) / n
    high_r = (b * si - 2 * B) / n

    if low_r > high_r:
        raise Exception('bad interval update')

    r = low_r
    for r in range(low_r, high_r+1):
        new_interval_begin = max(a, (2*B + r*n + si-1) / si)
        new_interval_end = min(b, (3*B - 1 + r*n) / si)
        new_interval = (new_interval_begin,new_interval_end)

        if new_interval_begin > new_interval_end:
            pass
        else:
            return [new_interval]


def step_4_computing_the_solution(rsa, B, M, S):
    n = rsa.key.N

    Mi = M[0]
    if Mi[0] == Mi[1]:
        message = (Mi[0] * modinv(1, n)) % n
        return message
    else:
        return None

def bleichenbacher_attack_simple(rsa, c):
    B = pow(2 , 8 * (rsa.key_length_bytes - 2))
    c0, M = c, [(2*B, 3*B-1)]

    S = step_2a_starting_the_search(rsa, B, c0)
    print "new s is: %s" % S
    M = step_3_narrowing_the_set_of_solutions(rsa, B, M, S)

    message = step_4_computing_the_solution(rsa, B, M, S)
    while message is None:
        S = step_2c_search_one_interval(rsa, B, M, c0, S)
        print "new s is: %s" % S
        M = step_3_narrowing_the_set_of_solutions(rsa, B, M, S)

        message = step_4_computing_the_solution(rsa, B, M, S)

    return integer_to_bytes(message, rsa.key_length_bytes)


def main():
    rsa = RSA_PKCS_1_5(1024) # length does not matter, we replace params
    message = 'kick it, CC'

    c = rsa.encrypt(message)
    m = rsa.decrypt(c)

    assert m == message
    assert padding_oracle(rsa, c) # pass oracle test
    assert not padding_oracle(rsa, c*2)

    ######################################################################

    #c = rsa.encrypt_no_pkcs(message)
    #m = rsa.decrypt_no_pkcs(c)

    #assert m[-len(message):] == message

    ######################################################################

    m = bleichenbacher_attack_simple(rsa, c)

    if m[-len(message):] == message:
        print("challenge 5.47 completed.")
    else:
        print("challenge 5.47 failed.")

if __name__ == "__main__":
    main()