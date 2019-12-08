import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from mersenne_twister_rng import MT19937
import time
import random

def generate_random():
    a = 2
    b = 10

    time.sleep(random.randint(a, b))

    seed = int(time.time())
    prg = MT19937(seed)
    
    time.sleep(random.randint(a, b))
    return seed, prg.extract_number()

def crack_seed(random_number):
    current_time = int(time.time())

    for possible_seed in range(current_time-100, current_time+40):
        prg = MT19937(possible_seed)
        if prg.extract_number() == random_number:
            return possible_seed

    assert False, 'did not cracked the seed'

def main():
    seed, random_number = generate_random()
    cracked_seed = crack_seed(random_number)
    
    if cracked_seed == seed:
        print("challenge 3.22 completed.")
    else:
        print("challenge 3.22 failed.")

if __name__ == '__main__':
    main()