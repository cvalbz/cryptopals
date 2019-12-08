from utils import base64_to_bytearray, hamming_distance, string_to_bytearray, unequal_chunks
from single_byte_xor_cipher import break_xor_cipher
from utils import alpha_and_printable_heuristic
from itertools import zip_longest
from repeating_key_xor import encrypt_repeating_key
from operator import itemgetter

assert hamming_distance(string_to_bytearray("this is a test"),
                        string_to_bytearray("wokka wokka!!!")) == 37

# block contains a || b
def normalized_edit_distance(block, key_size):
    a = block[0:key_size]
    b = block[key_size:(key_size*2)]
    edit_distance = hamming_distance(a, b)
    return 1.0 * edit_distance / key_size

def find_key_length(ciphertext):
    results = []

    for key_size in range(2, 40):
        block_length = 2 * key_size
        nblocks = len(ciphertext) // block_length
        blocks = unequal_chunks(ciphertext, block_length)

        distances = [normalized_edit_distance(i, key_size) for i in blocks]
        average = sum(distances) / nblocks

        results.append( (average, key_size) )

    return min(results, key=itemgetter(0))[1]

def transpose_chunks(chunks):
    transposed = map(list, zip_longest(*chunks, fillvalue=None))
    strip_none = [[i for i in c if i is not None] for c in transposed]
    return strip_none

def break_repeating_key_xor(ct):
    key_length = find_key_length(ct)
    chunks = unequal_chunks(ct, key_length)
    xor_ciphers = transpose_chunks(chunks)

    key_used = []
    for xor_cipher in xor_ciphers:
        score, message, key = break_xor_cipher(xor_cipher, alpha_and_printable_heuristic)
        key_used.append(key)

    return key_used

def main():
    with open("6.txt", "r") as f: ciphertext_b64 = f.read().replace("\n", "")
    ciphertext = base64_to_bytearray(ciphertext_b64)

    key = break_repeating_key_xor(ciphertext)
    print("challenge 1.6 key is: %s" % bytearray(key))
    message = encrypt_repeating_key(ciphertext, key)
    #print("the message is:\n%s" % message)

if __name__ == '__main__':
    main()