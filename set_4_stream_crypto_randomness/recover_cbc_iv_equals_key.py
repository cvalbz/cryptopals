import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, string_to_bytearray, xor
from pkcs7_padding import pad_to_mod_16, unpad_pkcs7
from aes_cbc_mode import decrypt_aes_cbc, encrypt_aes_cbc
import string

oracle_key = crypto_random_bytes(16)
iv = oracle_key

def encrypt_user_data_cbc(user_data):
    user_data = user_data.replace(";", "")
    user_data = user_data.replace("=", "")

    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    plaintext = string_to_bytearray(prefix + user_data + suffix)

    to_encrypt = pad_to_mod_16(plaintext)
    ciphertext = encrypt_aes_cbc(to_encrypt, oracle_key, iv)

    return ciphertext

def decrypt_and_check_url(ciphertext):
    plaintext = decrypt_aes_cbc(ciphertext, oracle_key, iv)
    plaintext = unpad_pkcs7(plaintext)

    for c in plaintext:
        if chr(c) not in string.printable:
            raise Exception(plaintext)

    return True

def recover_key():
    ciphertext = encrypt_user_data_cbc("1234")

    c1 = ciphertext[0:16]
    c2 = ciphertext[16:32]
    c3 = ciphertext[32:48]

    prev = ciphertext[-32:-16]
    padding_block = ciphertext[-16:]

    try:
        decrypt_and_check_url(c1 + bytearray([0]*16) + c1 + prev + padding_block)
    except Exception as e:
        message = e.args[0]

        p1 = message[0:16]
        p3 = message[32:48]

        return xor(p1, p3)

def main():
    key = recover_key()

    if key == oracle_key:
        print("challenge 4.27 completed.")
    else:
        print("challenge 4.27 failed.")

if __name__ == '__main__':
    main()