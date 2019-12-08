from Crypto.Cipher import AES
from utils import base64_to_bytearray, string_to_bytearray

def decrypt_aes_128_ecb(ciphertext, key):
    assert type(ciphertext) is bytearray

    ciphertext_bytes = bytes(ciphertext)
    key_bytes = bytes(key)

    obj = AES.new(key_bytes, AES.MODE_ECB)
    message_bytes = obj.decrypt(ciphertext_bytes)
    return bytearray(message_bytes)

def encrypt_aes_128_ecb(plaintext, key):
    assert type(plaintext) is bytearray
    
    plaintext_bytes = bytes(plaintext)
    key_bytes = bytes(key)

    obj = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext_bytes = obj.encrypt(plaintext_bytes)
    return bytearray(ciphertext_bytes)

def test_aes_ecb():
    # sanity check for encryption/decryption
    test_key = string_to_bytearray("A"*16)
    test_text = string_to_bytearray("12345678"*2)

    enc = encrypt_aes_128_ecb(test_text, test_key)
    if decrypt_aes_128_ecb(enc, test_key) != test_text:
        raise Exception("aes ecb is not working properly !!!")

def main():
    test_aes_ecb()

    with open("7.txt", "r") as f: ciphertext_b64 = f.read().replace("\n", "")
    ciphertext_bt = base64_to_bytearray(ciphertext_b64)
    key = string_to_bytearray("YELLOW SUBMARINE")

    message = decrypt_aes_128_ecb(ciphertext_bt, key)
    assert b"I'm back and I'm ringin' the bell" in message
    print("challenge 1.7 completed.")

if __name__ == '__main__':
    main()
