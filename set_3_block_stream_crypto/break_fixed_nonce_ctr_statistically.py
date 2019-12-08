import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')

from utils import base64_to_bytearray, crypto_random_bytes, xor_diff_lengths, unequal_chunks
from aes_ctr_mode import decrypt_aes_ctr, encrypt_aes_ctr
from break_repeating_key_xor import transpose_chunks, break_xor_cipher
from utils import alpha_and_printable_heuristic
from single_byte_xor_cipher import break_xor_cipher
import string

def create_repeating_key_ciphertext(ciphertexts):
    repeating_key_length = min([len(i) for i in ciphertexts])
    ciphertexts_truncated = [i[:repeating_key_length] for i in ciphertexts]

    ciphertext = []
    for ct in ciphertexts_truncated:
        ciphertext.extend(ct)

    return repeating_key_length, ciphertext

def break_ctr(ciphertexts):
    key_length, ciphertext = create_repeating_key_ciphertext(ciphertexts)

    chunks = unequal_chunks(ciphertext, key_length)
    xor_ciphers = transpose_chunks(chunks)

    key_used = []
    for xor_cipher in xor_ciphers:
        score, message, key = break_xor_cipher(xor_cipher, alpha_and_printable_heuristic)
        key_used.append(key)

    return key_used

BLOCK_SIZE = 16
KEY = crypto_random_bytes(BLOCK_SIZE)
NONCE = bytearray([0] * 8)

with open('20.txt', 'r') as f: lines = f.readlines()
messages_b64 = [line.replace("\n", "") for line in lines]
messages = [base64_to_bytearray(i) for i in messages_b64]

ciphertexts = [encrypt_aes_ctr(i, KEY, NONCE) for i in messages]

key_stream_length = max([len(i) for i in ciphertexts])
key_stream = [0] * key_stream_length

def main():
    key_stream = break_ctr(ciphertexts)

    messages_decrypted = [xor_diff_lengths(key_stream, i) for i in ciphertexts]
    # for ix, m in enumerate(messages_decrypted):
    #   print(ix, m)

    message_corrected = b"You think you're ruffer, then suffer the consequences"
    message_corrected_ix = 33

    key_stream = xor_diff_lengths(bytearray(message_corrected), ciphertexts[message_corrected_ix])
    messages_decrypted = [xor_diff_lengths(key_stream, i) for i in ciphertexts]
    # for ix, m in enumerate(messages_decrypted):
    #   print(ix, m)

    print("challenge 3.20 completed.")

if __name__ == '__main__':
    main()