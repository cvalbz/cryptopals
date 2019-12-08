"""
TODO update this for python3: need python3 implementation of md4
"""

import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray, string_to_bytearray
import md4_keyed_mac as md4_km
import struct

key = crypto_random_bytes(random_integer(8, 64))

def sign(message):
    to_sign = str(key + message)

    m = md4_km.MD4()
    m.update(to_sign)
    return m.digest()

def verify_signature(sig, message):
    m = md4_km.MD4()
    m.update(str(key + message))
    return m.digest() == sig

def verify_signature_admin(sig, message):
    return verify_signature(sig, message) and b"admin=true" in message

def forge_signature(message, signature, append):
    state = md4_km.get_md4_registers_from_signature(signature)

    results = []
    for key_length in range(8, 64):
        dummy_key =  bytes("A" * key_length, 'ascii')
        glue_padding = md4_km.md_padding(dummy_key + message)

        fake_message = dummy_key + message + glue_padding

        forged_sig = md4_km.roll_cascade_function( state, fake_message, append)
        results.append( (forged_sig, message + glue_padding + append) )

    return results

def main():
    message = string_to_bytearray("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
    append = string_to_bytearray(";admin=true")

    signature = sign(message)
    assert verify_signature(signature, message)

    forge_signature_candidates = forge_signature(message, signature, append)
    
    forged = [(f, m) for (f, m) in forge_signature_candidates if verify_signature_admin(f, m)]
    if len(forged) > 0:
        print("challenge 4.30 completed.")
    else:
        print("challenge 4.30 failed.")

if __name__ == '__main__':
    main()