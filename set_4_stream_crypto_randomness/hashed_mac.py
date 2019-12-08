import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from sha1_keyed_mac import sha1
from utils import xor, string_to_bytearray, hexstr2bytearray

BLOCKSIZE = 64

def hmac(key, message):
    if (len(key) > BLOCKSIZE):
        key = bytearray(sha1(key).decode('hex')) # keys longer than BLOCKSIZE are shortened

    if (len(key) < BLOCKSIZE):
        # keys shorter than BLOCKSIZE are zero-padded (where + is concatenation)
        key = key + bytearray([0x00] * (BLOCKSIZE - len(key))) # Where * is repetition.

    o_key_pad = xor(bytearray([0x5c] * BLOCKSIZE), key)
    i_key_pad = xor(bytearray([0x36] * BLOCKSIZE), key)

    h1 = sha1(i_key_pad + string_to_bytearray(message))
    return sha1(o_key_pad + hexstr2bytearray(h1))