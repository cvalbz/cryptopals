import sys
sys.path.insert(0, '../set_1_basics')
from utils import random_integer, crypto_random_bytes, string_to_bytearray
from aes_ecb_mode import encrypt_aes_128_ecb
from aes_cbc_mode import encrypt_aes_cbc
from detect_aes_in_ecb_mode import has_repeated_blocks
from pkcs7_padding import pad_to_mod_16
from random import choice

def encryption_oracle_ecb_cbc(bt):
    key = crypto_random_bytes(16)
    iv = crypto_random_bytes(16)
    mode = choice(['ecb', 'cbc'])

    begin_pad = crypto_random_bytes(random_integer(5,10))
    end_pad = crypto_random_bytes(random_integer(5,10))
    to_encrypt = pad_to_mod_16(begin_pad + bt + end_pad)

    if mode == 'ecb':
        ciphertext = encrypt_aes_128_ecb(to_encrypt, key)
    else:
        ciphertext = encrypt_aes_cbc(to_encrypt, key, iv)

    # do not cheat, use mode for validation only
    return ciphertext, mode

def detection_oracle(ciphertext):
    return 'ecb' if has_repeated_blocks(ciphertext) else 'cbc'
    
def main():
    true_modes = []
    detected_modes = []

    for trial in range(0, 100):
        crafted_plaintext = string_to_bytearray("A"*64)

        ciphertext, true_mode = encryption_oracle_ecb_cbc(crafted_plaintext)
        detected_mode = detection_oracle(ciphertext)

        true_modes.append(true_mode)
        detected_modes.append(detected_mode)

    if detected_modes == true_modes:
        print("challenge 2.11 completed.")
    else:
        print("challenge 2.11 failed.")

if __name__ == '__main__':
    main()