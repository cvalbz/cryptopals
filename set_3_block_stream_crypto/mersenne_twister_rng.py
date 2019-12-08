import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import base64_to_bytearray
from numba import jitclass, jit
from numba import int32, int64
import numpy as np

spec = [
    ('index', int32), # a simple scalar field
    ('mt', int64[:]), # an array field
]

@jit
def _int32(x):
    # Get the 32 least significant bits.
    return 0xFFFFFFFF & x

@jitclass(spec)
class MT19937:
    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624

        #self.mt = [0] * 624
        self.mt = np.zeros(624, dtype=np.int64)
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = _int32(1812433253 *
                                (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18

        self.index = self.index + 1
        return _int32(y)

    def twist(self):
        for i in range(624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

def main():
    prg1 = MT19937(1)
    prg2 = MT19937(1)

    assert ([prg1.extract_number() for _ in range(1000)] == 
            [prg2.extract_number() for _ in range(1000)])

    print("challenge 3.21 completed.")

if __name__ == '__main__':
    main()