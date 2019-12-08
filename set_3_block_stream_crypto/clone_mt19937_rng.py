import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from mersenne_twister_rng import MT19937, _int32
import numpy as np

def generate_randoms():
    seed = 666
    prg = MT19937(seed)
    return prg, [prg.extract_number() for _ in range(624)]

def getMSB(x, n):
    if n < 0:
        return 0
    return (x >> (31 - n)) & 1

def setMSB(x, n, b):
    return x | (b << (31 - n))

def undoRightShiftXor(y, s):
    z = 0
    for i in range(32):
        z = setMSB(z, i, getMSB(y, i) ^ getMSB(z, i - s))
    return z

def getLSB(x, n):
    if n < 0:
        return 0
    return (x >> n) & 1

def setLSB(x, n, b):
    return x | (b << n)

def undoLeftShiftXorAnd(y, s, k):
    z = 0
    for i in range(32):
       z = setLSB(z, i, getLSB(y, i) ^ (getLSB(z, i - s) & getLSB(k, i)))
    return z

def untemper(y):
    y = undoRightShiftXor(y, 18)
    y = undoLeftShiftXorAnd(y, 15, 4022730752)
    y = undoLeftShiftXorAnd(y, 7, 2636928640)
    y = undoRightShiftXor(y, 11)
    return y

def main():
    prg, random_numbers = generate_randoms()

    untempered_numbers = np.array([untemper(i) for i in random_numbers])

    cloned_prg = MT19937(123)
    cloned_prg.mt = untempered_numbers

    new_numbers = [(prg.extract_number(), cloned_prg.extract_number())  for _ in range(1000)]

    for i, j in new_numbers:
        assert i == j
    
    print("challenge 3.23 completed.")

if __name__ == '__main__':
    main()