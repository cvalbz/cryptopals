import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from mersenne_twister_rng import MT19937
from utils import xor, random_integer, crypto_random_bytes, string_to_bytearray
import struct
import time
import random

def generate_bytes(prg, nbytes):
    prg_bytes = bytearray([])

    for i in range(nbytes // 4 + 1):
        nr = prg.extract_number()
        prg_bytes.extend(bytearray(struct.pack(">I", nr)))

    return prg_bytes[:nbytes]

def cipher_encrypt(plaintext, key):
    assert key < 2**16, '16-bit key please'
    assert key > 0, '16-bit key please'

    prg = MT19937(key)
    key_stream = generate_bytes(prg, len(plaintext))

    return xor(plaintext, key_stream)

def cipher_decrypt(ciphertext, key):
    assert key < 2**16, '16-bit key please'
    assert key >= 0, '16-bit key please'

    prg = MT19937(key)
    key_stream = generate_bytes(prg, len(ciphertext))

    return xor(ciphertext, key_stream)

def test_cipher():
    key = 2**16 - 6666
    plaintext = bytearray(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")

    ciphertext = cipher_encrypt(plaintext, key)
    decrypted = cipher_decrypt(ciphertext, key)
    assert decrypted == plaintext

def encryption_oracle():
    key = random_integer(0, 2**16 - 1)
    prefix = crypto_random_bytes(random_integer(0, 200))
    message = prefix + b"A" * 14

    ciphertext = cipher_encrypt(message, key)
    return key, ciphertext

def break_mt19937_stream_cipher(ciphertext):
    for key_candidate in range(0, 2**16-1):
        message = cipher_decrypt(ciphertext, key_candidate)
        if message[len(message)-14:] == string_to_bytearray("A" * 14):
            return key_candidate

    raise Exception('key not found')

def generate_password_reset_token():
    seed = int(time.time())
    prg = MT19937(seed)
    return prg.extract_number()

def analyze_password_reset_token(token):
    current_time = int(time.time())

    for possible_seed in range(current_time - 100, current_time + 50):
        prg = MT19937(possible_seed)
        if prg.extract_number() == token:
            return True

    return False

def main():
    test_cipher()

    key, ciphertext =  encryption_oracle()
    key_found = break_mt19937_stream_cipher(ciphertext)

    assert key == key_found, 'breaking stream cipher not working properly'

    token = generate_password_reset_token()
    assert analyze_password_reset_token(token) == True

    random_token = random_integer(0, 2**32 - 1)
    assert analyze_password_reset_token(random_token) == False

    print("challenge 3.24 completed.")

import cProfile
if __name__ == '__main__':
    main()