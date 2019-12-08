import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of, string_to_bytearray
import sha1_keyed_mac as sha1_km
import struct

key = crypto_random_bytes(random_integer(8, 64))

def sign(message):
    return sha1_km.sha1_keyed_mac(key, message)

def verify_signature(sig, message):
    return sig == sha1_km.sha1_keyed_mac(key, message)

def verify_signature_admin(sig, message):
    return verify_signature(sig, message) and b"admin=true" in message

def get_sha_registers_from_signature(signature_hex):
    ch = list(chunks_of(signature_hex, 8))

    h0 = int("".join(ch[0]), 16)
    h1 = int("".join(ch[1]), 16)
    h2 = int("".join(ch[2]), 16)
    h3 = int("".join(ch[3]), 16)
    h4 = int("".join(ch[4]), 16)

    return h0, h1, h2, h3, h4

def forge_signature(message, signature, append):
    state = get_sha_registers_from_signature(signature)
    
    results = []
    for key_length in range(8, 65):
        dummy_key_bytes = bytes("A" * key_length, 'ascii')
        glue_padding = sha1_km.md_padding(dummy_key_bytes + message)
        fake_message = dummy_key_bytes + message + glue_padding

        forged_sig = sha1_km.roll_cascade_function(state, fake_message, append)
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
        print("challenge 4.29 completed.")
    else:
        print("challenge 4.29 failed.")

if __name__ == '__main__':
    main()