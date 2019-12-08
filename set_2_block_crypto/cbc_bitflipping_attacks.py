import sys
sys.path.insert(0, '../set_1_basics')
from utils import crypto_random_bytes, base64_to_bytearray, string_to_bytearray, random_integer
from pkcs7_padding import pad_to_mod_16, unpad_pkcs7
from aes_cbc_mode import decrypt_aes_cbc, encrypt_aes_cbc
from utils import str2bin, bin2str

oracle_key = crypto_random_bytes(16)
iv = crypto_random_bytes(16)

def encrypt_user_data_cbc(user_data):
    user_data = user_data.replace(";", "")
    user_data = user_data.replace("=", "")
    plaintext = "comment1=cooking%20MCs;userdata=" + user_data + ";comment2=%20like%20a%20pound%20of%20bacon"

    to_encrypt = pad_to_mod_16(string_to_bytearray(plaintext))
    return encrypt_aes_cbc(to_encrypt, oracle_key, iv)

def decrypt_and_check_admin(ciphertext):
    plaintext = decrypt_aes_cbc(ciphertext, oracle_key, iv)
    plaintext = unpad_pkcs7(plaintext)
    return b';admin=true;' in plaintext

def flip_bit(ciphertext, ix):
    assert type(ciphertext) is bytearray

    ciphertext_copy = bytearray(ciphertext)

    byte_ix = ix // 8
    bit_ix = ix % 8
    ciphertext_copy[byte_ix] ^= (1 << 7 - bit_ix)

    return ciphertext_copy
    
def main():
    ciphertext = encrypt_user_data_cbc("ZZZZZ:admin<true")

    first_bit_flip = flip_bit(ciphertext, 128 + 47) # add 1 to ':'
    second_bit_flip = flip_bit(first_bit_flip, 128 + 95) # add 1 to '<'

    if decrypt_and_check_admin(second_bit_flip):
        print("challenge 2.16 completed.")
    else:
        print("challenge 2.16 failed.")

if __name__ == '__main__':
    main()