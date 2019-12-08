import sys
sys.path.insert(0, '../set_1_basics')
from utils import crypto_random_bytes, base64_to_bytearray, string_to_bytearray
from aes_ecb_mode import encrypt_aes_128_ecb
from pkcs7_padding import pad_to_mod_16
from ecb_cbc_detection_oracle import detection_oracle

oracle_key = crypto_random_bytes(16)
secret_b64_string = '''
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
'''
secret = base64_to_bytearray(secret_b64_string)

def encryption_oracle_ecb(plaintext):
    to_encrypt = pad_to_mod_16(plaintext + secret)
    return encrypt_aes_128_ecb(to_encrypt, oracle_key)

def discover_block_size_in_bytes():
    tried = ""
    plaintext = string_to_bytearray(tried)
    initial_length = len(encryption_oracle_ecb(plaintext))

    # detect when there is a change in ciphertext length
    length_detected = False
    while not length_detected:
        tried += "A"
        plaintext = string_to_bytearray(tried)
        ciphertext_length = len(encryption_oracle_ecb(plaintext))

        if ciphertext_length > initial_length:
            length_detected = True
            payload_length_at_change = len(tried)
            new_length = ciphertext_length

    # find the block size
    block_size_detected = False
    while not block_size_detected:
        tried += "A"
        plaintext = string_to_bytearray(tried)
        ciphertext_length = len(encryption_oracle_ecb(plaintext))

        if ciphertext_length > new_length:
            block_size_detected = True

    return len(tried) - payload_length_at_change

def detect_ecb_mode(block_size):
    crafted_payload = string_to_bytearray("A" * block_size * 3)
    ciphertext = encryption_oracle_ecb(crafted_payload)
    return detection_oracle(ciphertext)

def discover_secret_length(block_size):
    tried = "A" * block_size * 2
    plaintext = string_to_bytearray(tried)
    ciphertext = encryption_oracle_ecb(plaintext)
    initial_length = len(ciphertext)

    # first two blocks are identical
    assert ciphertext[0:block_size] == ciphertext[block_size:block_size*2]

    # detect when there is a change in ciphertext length
    length_detected = False
    while not length_detected:
        tried += "B"
        plaintext = string_to_bytearray(tried)
        ciphertext_length = len(encryption_oracle_ecb(plaintext))

        if ciphertext_length > initial_length:
            length_detected = True
            payload_length_at_change = len(tried)
            new_length = ciphertext_length

    # padding used is block_size
    return new_length - payload_length_at_change - block_size

def find_one_byte(padding, so_far):
    ciphertext = encryption_oracle_ecb(padding)
    interesting_bytes = ciphertext[0:len(padding + so_far) + 1]

    for byte_candidate in range(0, 255):
        crafted_plaintext_full = padding + so_far + bytearray([byte_candidate])
        tried_ciphertext = encryption_oracle_ecb(crafted_plaintext_full)

        if tried_ciphertext[:len(crafted_plaintext_full)] == interesting_bytes:
            # found that one byte that we are looking for
            return byte_candidate

    raise Exception("find one byte did not work !!!")

def find_secret(block_size, secret_length):
    discovered_so_far = bytearray([])

    for i in range(secret_length):
        blocks_to_craft = len(discovered_so_far) // block_size + 1
        padding_str = "A" * (blocks_to_craft * block_size - 1 - len(discovered_so_far))
        padding = string_to_bytearray(padding_str)

        assert (len(padding) + len(discovered_so_far) + 1) % block_size == 0

        found = find_one_byte(padding, discovered_so_far)
        discovered_so_far.append(found)

    return discovered_so_far

def main():
    block_size = discover_block_size_in_bytes()

    assert block_size == 16
    assert detect_ecb_mode(block_size) == 'ecb'

    secret_length = discover_secret_length(block_size)
    assert secret_length == len(secret)

    # find secret
    discovered = find_secret(block_size, secret_length)
    if discovered == secret:
        print("challenge 2.12 completed.")
    else:
        print("challenge 2.12 failed.")

if __name__ == '__main__':
    main()