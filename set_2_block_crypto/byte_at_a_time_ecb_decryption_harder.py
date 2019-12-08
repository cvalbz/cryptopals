import sys
sys.path.insert(0, '../set_1_basics')
from utils import crypto_random_bytes, base64_to_bytearray, string_to_bytearray, random_integer
from aes_ecb_mode import encrypt_aes_128_ecb
from pkcs7_padding import pad_to_mod_16
from ecb_cbc_detection_oracle import detection_oracle
import byte_at_a_time_ecb_decryption_simple as byte_at_a_time_simple
from utils import chunks_of_bytearray
from itertools import groupby

oracle_key = crypto_random_bytes(16)
secret_b64_string = '''
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
'''

secret = base64_to_bytearray(secret_b64_string)
padding = crypto_random_bytes(random_integer(1,30))

def encryption_oracle_ecb(plaintext):
    to_encrypt = pad_to_mod_16(padding + plaintext + secret)
    return encrypt_aes_128_ecb(to_encrypt, oracle_key)

def _check_magic_blocks_number(magic, ct, block_size):
    blocks = chunks_of_bytearray(ct, block_size)
    repeating_blocks_grouped = [list(j) for i,j in groupby(blocks)]
    repeating_blocks_sizes = [len(i) for i in repeating_blocks_grouped]

    # padding is multiple of block_size
    if magic in repeating_blocks_sizes:
        # find the position of the first magic block
        ix = repeating_blocks_sizes.index(magic)
        return sum(repeating_blocks_sizes[:ix])

    return None

def discover_padding_length(block_size):
    magic_blocks_number = 5
    tried = "A" * block_size * magic_blocks_number
    plaintext = string_to_bytearray(tried)
    ciphertext = encryption_oracle_ecb(plaintext)

    r = _check_magic_blocks_number(magic_blocks_number, ciphertext, block_size)
    i = 0
    while r is None:
        i += 1
        plaintext = string_to_bytearray(i * "B" + tried)
        ciphertext = encryption_oracle_ecb(plaintext)
        r = _check_magic_blocks_number(magic_blocks_number, ciphertext, block_size)

    # we "padded" the padding
    padding_length = r * block_size - i
    return padding_length

def discover_secret_length(block_size, padding_length):
    if padding_length % block_size == 0:
        pad_for_padding = ""
    else:
        pad_for_padding = "X" * (block_size - padding_length % block_size)
        assert len(pad_for_padding) < block_size

    tried = "A" * block_size * 2
    plaintext = string_to_bytearray(pad_for_padding + tried)
    ciphertext = encryption_oracle_ecb(plaintext)
    initial_length = len(ciphertext)

    # first two controlled blocks are identical
    padding_ciphertext_length = padding_length + len(pad_for_padding)
    controlled_ciphertext = ciphertext[padding_ciphertext_length:]
    assert controlled_ciphertext[0:block_size] == controlled_ciphertext[block_size:block_size*2]

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
    return new_length - payload_length_at_change - block_size - padding_length

def find_one_byte(controlled, junk_length, pad_for_padding_length, so_far):
    ciphertext = encryption_oracle_ecb(controlled)
    interesting_bytes = ciphertext[junk_length:][0:len(controlled + so_far) - pad_for_padding_length + 1]

    for byte_candidate in range(0, 255):
        crafted_plaintext_full = controlled + so_far + bytearray([byte_candidate])
        tried_ciphertext = encryption_oracle_ecb(crafted_plaintext_full)[junk_length:]

        if tried_ciphertext[:len(crafted_plaintext_full) - pad_for_padding_length] == interesting_bytes:
            # found that one byte that we are looking for
            return byte_candidate

    raise Exception("find one byte did not work !!!")

def find_secret(block_size, padding_length, secret_length):
    if padding_length % block_size == 0:
        pad_for_padding = ""
    else:
        pad_for_padding = "X" * (block_size - padding_length % block_size)
        assert len(pad_for_padding) < block_size

    discovered_so_far = bytearray([])

    for i in range(secret_length):
        blocks_to_craft = len(discovered_so_far) // block_size + 1
        controlled_str = pad_for_padding + "A" * (blocks_to_craft * block_size - 1 - len(discovered_so_far))
        controlled = string_to_bytearray(controlled_str)

        assert (padding_length + len(controlled) + len(discovered_so_far) + 1) % block_size == 0

        uninteresting_junk_length = padding_length + len(pad_for_padding)
        found = find_one_byte(controlled, uninteresting_junk_length, len(pad_for_padding), discovered_so_far)
        discovered_so_far.append(found)

    return discovered_so_far

def main():
    block_size = byte_at_a_time_simple.discover_block_size_in_bytes()

    assert block_size == 16
    assert byte_at_a_time_simple.detect_ecb_mode(block_size) == 'ecb'

    padding_length = discover_padding_length(block_size)
    assert padding_length == len(padding)

    secret_length = discover_secret_length(block_size, padding_length)
    assert secret_length == len(secret) 

    # find secret
    discovered = find_secret(block_size, padding_length, secret_length)

    if discovered == secret:
        print("challenge 2.14 completed.")
    else:
        print("challenge 2.14 failed.")

if __name__ == '__main__':
    main()