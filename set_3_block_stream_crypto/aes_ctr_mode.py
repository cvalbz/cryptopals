import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
from utils import base64_to_bytearray, string_to_bytearray, chunks_of_bytearray, xor
from aes_ecb_mode import decrypt_aes_128_ecb, encrypt_aes_128_ecb
from utils import bt_to_lit_end_int, int_to_lit_end_bt
from math import ceil

def encrypt_aes_ctr(plaintext, key, nonce):
    assert len(key) == 16
    assert len(nonce) == 8

    counter = int(ceil(len(plaintext) / 16))
    keystream = []

    for i in range(counter):
        to_encrypt = nonce + int_to_lit_end_bt(i)

        encrypted_counter = encrypt_aes_128_ecb(to_encrypt, key)
        keystream.extend(encrypted_counter)

    keystream = keystream[:len(plaintext)]
    return xor(plaintext, keystream)

def decrypt_aes_ctr(ciphertext, key, nonce):
    assert len(key) == 16
    assert len(nonce) == 8

    return encrypt_aes_ctr(ciphertext, key, nonce)

def test_aes_ctr():
    # sanity check for encryption/decryption
    test_key = string_to_bytearray("A"*16)
    test_text = string_to_bytearray("12345678"*4)
    test_nonce = string_to_bytearray("B"*8)

    encrypted = encrypt_aes_ctr(test_text, test_key, test_nonce)
    decrypted = decrypt_aes_ctr(encrypted, test_key, test_nonce)
    if  decrypted != test_text:
        raise Exception("aes ctr is not working properly !!!")

def main():
    test_aes_ctr()

    ciphertext_b64 = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    ciphertext_bt = base64_to_bytearray(ciphertext_b64)

    key = string_to_bytearray("YELLOW SUBMARINE")
    nonce = bytearray([0]*8)
    message = decrypt_aes_ctr(ciphertext_bt, key, nonce)

    #print message
    assert b"VIP Let's kick it" in message
    print("challenge 3.18 completed.")

if __name__ == '__main__':
    main()