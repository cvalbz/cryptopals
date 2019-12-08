import sys
sys.path.insert(0, '../set_1_basics')
from utils import base64_to_bytearray, string_to_bytearray, chunks_of_bytearray, xor
from aes_ecb_mode import decrypt_aes_128_ecb, encrypt_aes_128_ecb
from pkcs7_padding import pad_to_mod_16, unpad_pkcs7

def decrypt_aes_cbc(ciphertext, key, iv):
    assert len(key) == 16
    assert len(iv) == 16
    assert len(ciphertext) % 16 == 0

    blocks = chunks_of_bytearray(ciphertext, len(key))
    initial = iv
    
    result = []
    for block in blocks:
        decrypted_block = decrypt_aes_128_ecb(block, key)
        plaintext_block = xor(decrypted_block, initial)

        result.extend(plaintext_block)
        initial = block

    return bytearray(result)

def encrypt_aes_cbc(plaintext, key, iv):
    assert len(plaintext) % 16 == 0
    assert len(key) == 16
    assert len(iv) == 16

    blocks = chunks_of_bytearray(plaintext, len(key))
    initial = iv

    result = []
    for block in blocks:
        to_encrypt = xor(initial, block)
        ciphertext_block = encrypt_aes_128_ecb(to_encrypt, key)
        result.extend(ciphertext_block)
        initial = ciphertext_block

    return bytearray(result)

def test_aes_cbc():
    # sanity check for encryption/decryption
    test_key = string_to_bytearray("A"*16)
    test_text = string_to_bytearray("12345678"*4)
    test_iv = string_to_bytearray("B"*16)
    encrypted = encrypt_aes_cbc(test_text, test_key, test_iv)
    decrypted = decrypt_aes_cbc(encrypted, test_key, test_iv)
    if  decrypted != test_text:
        raise Exception("aes cbc is not working properly !!!")

def main():
    test_aes_cbc()

    with open("10.txt", "r") as f: ciphertext_b64 = f.read().replace("\n", "")
    ciphertext_bt = base64_to_bytearray(ciphertext_b64)

    key = string_to_bytearray("YELLOW SUBMARINE")
    iv = bytearray([0]*16)

    message = decrypt_aes_cbc(ciphertext_bt, key, iv)
    assert b"I'm back and I'm ringin' the bell" in message
    print("challenge 2.10 completed.")

if __name__ == '__main__':
    main()