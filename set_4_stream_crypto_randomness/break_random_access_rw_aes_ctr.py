import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import unequal_chunks, xor, string_to_bytearray
from aes_ctr_mode import encrypt_aes_ctr, decrypt_aes_ctr

with open('25.txt', 'r') as f:
    message = string_to_bytearray(f.read().replace("\n", ""))
KEY = string_to_bytearray("YELLOW SUBMARINE")
NONCE = bytearray([0]*8)
ciphertext = encrypt_aes_ctr(message, KEY, NONCE)

def edit(offset, newtext):
    m = decrypt_aes_ctr(ciphertext, KEY, NONCE)
    m[offset:offset+len(newtext)] = newtext

    return encrypt_aes_ctr(m, KEY, NONCE)

def break_easy_way():
    total_length = len(ciphertext)

    newtext = bytearray([0] * total_length)
    offset = 0

    keystream = edit(offset, newtext)
    return xor(ciphertext, keystream)


def break_little_harder_way():
    newtext = string_to_bytearray('FIXED VALUE')
    chunk_length = len(newtext)

    chunks = unequal_chunks(ciphertext, chunk_length)
    keystream = bytearray([])

    for ix, chunk in enumerate(chunks):
        start = ix * chunk_length
        end = start + len(chunk)

        new_ciphertext = edit(start, newtext)[start:end]

        keystream_chunk = xor(new_ciphertext, newtext[:len(new_ciphertext)])
        keystream.extend(keystream_chunk)

    return xor(ciphertext, keystream)


def main():
    m1 = break_easy_way()
    m2 = break_little_harder_way()

    if message == m1 and message == m2:
        print("challenge 4.25 completed.")
    else:
        print("challenge 4.25 failed.")

if __name__ == '__main__':
    main()