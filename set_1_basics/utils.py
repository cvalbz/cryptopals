import base64
import binascii
import string
import os
import random
import struct
import itertools

# bytearray functions
def hex_string_to_bytearray(hex_string):
    return bytearray.fromhex(hex_string)

def string_to_bytearray(s):
    return bytearray(s, "ascii")

def bytearray_to_base64(bt):
    return base64.b64encode(bt).decode("ascii")

def base64_to_bytearray(b64):
    return bytearray(base64.b64decode(b64))

def bytearray_to_hex_string(bt):
    return binascii.hexlify(bt).decode("ascii")

def xor(a, b):
    if len(a) != len(b):
        raise Exception("different lengths")

    xored = [i^j for i,j in zip(a,b)]
    return bytearray(xored)

def xor_diff_lengths(a, b):
    xored = [i^j for i,j in zip(a,b)]
    return bytearray(xored)

def printable_chars_heuristic(message):
    chars = [chr(i) for i in message]
    printable = [c for c in chars if c in string.printable]
    return 100.0 * len(printable) / len(message)

def alpha_or_punctuation_heuristic(message):
    chars = [chr(i) for i in message]
    printable = [c for c in chars if c.isalpha() or c in " .,?!'-\n"]
    return 100.0 * len(printable) / len(message)

def alpha_and_printable_heuristic(message):
    return alpha_or_punctuation_heuristic(message) + printable_chars_heuristic(message)

def hamming_distance(a, b):
    xored = [i^j for i,j in zip(a,b)]

    bits = "".join([bin(i)[2:] for i in xored])
    return len([i for i in bits if i == '1'])

def chunks_of(lst, n):
    if len(lst) % n != 0:
        raise Exception("chunks will not have equal length")

    return map(list, zip(*[iter(lst)]*n))

def chunks_of_bytearray(bt, n):
    if len(bt) % n != 0:
        raise Exception("chunks will not have equal length")

    return list(map(bytearray, map(list, zip(*[iter(bt)]*n))))

def _grouper(iterable, n):
    it = iter(iterable)
    while True:
         chunk = tuple(itertools.islice(it, n))
         if not chunk:
                 return
         yield chunk

def unequal_chunks(bt, n):
    ch = map(bytearray, list(_grouper(bt, n)))
    return ch
    
def crypto_random_bytes(n):
    return os.urandom(n)

def crypto_non_zero_random_bytes(n):
    result = []
    while len(result) < n:
        b = crypto_random_bytes(1)
        if b[0] is not 0:
            result.append(b[0])

    return bytearray(result)    

def random_integer(a, b):
    return random.randint(a, b)

def bt_to_lit_end_int(bt):
    return struct.unpack('<Q', bt)[0]

def int_to_lit_end_bt(int):
    return bytearray(struct.pack('<Q', int))

# string functions

def strxor(a, b): # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])
 
def hexxor(a, b): # xor two hex strings (trims the longer input)
    ha = a.decode('hex')
    hb = b.decode('hex')
    return "".join([chr(ord(x) ^ ord(y)).encode('hex') for (x, y) in zip(ha, hb)])
 
def bitxor(a, b): # xor two bit strings (trims the longer input)
    return "".join([str(int(x)^int(y)) for (x, y) in zip(a, b)])
 
def str2bin(ss):
    """
        Transform a string (e.g. 'Hello') into a string of bits
    """
    bs = ''
    for c in ss:
        bs = bs + bin(ord(c))[2:].zfill(8)
    return bs
 
def hex2bin(hs):
    """
        Transform a hex string (e.g. 'a2') into a string of bits (e.g.10100010)
    """
    bs = ''
    for c in hs:
        bs = bs + bin(int(c,16))[2:].zfill(4)
    return bs
 
def bin2hex(bs):
    """
        Transform a bit string into a hex string
    """
    return hex(int(bs,2))[2:-1]
 
def byte2bin(bval):
    """
        Transform a byte (8-bit) value into a bitstring
    """
    return bin(bval)[2:].zfill(8)
 
def str2int(ss):
    """
        Transform a string (e.g. 'Hello') into a (long) integer by converting
        first to a bistream
    """
    bs = str2bin(ss)
    li = int(bs, 2)
    return li
 
def int2hexstring(bval):
    """
        Transform an int value into a hexstring (even number of characters)
    """
    hs = hex(bval)[2:]
    lh = len(hs)
    return hs.zfill(lh + lh%2)
 
def bin2str(bs):
    """
        Transform a binary srting into an ASCII string
    """
    n = int(bs, 2)
    return binascii.unhexlify('%x' % n)

def hexstr2bytearray(s):
    return bytearray(bytes.fromhex(s))

def bytearray2hexstring(b):
    return binascii.hexlify(b).decode('ascii')