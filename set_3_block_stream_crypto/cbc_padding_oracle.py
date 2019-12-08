import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
from utils import crypto_random_bytes, base64_to_bytearray, string_to_bytearray, random_integer, xor, chunks_of_bytearray
from pkcs7_padding import pad_to_mod_16, valid_pkcs7_padding, unpad_pkcs7
from aes_cbc_mode import decrypt_aes_cbc, encrypt_aes_cbc

messages = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

BLOCK_SIZE = 16
ORACLE_KEY = crypto_random_bytes(BLOCK_SIZE)
ORACLE_IV = crypto_random_bytes(BLOCK_SIZE)

def cbc_encryption_oracle():
    messages_encrypted = []
    for message in messages:
        message_to_encrypt = base64_to_bytearray(message)
        message_to_encrypt_padded = pad_to_mod_16(message_to_encrypt)

        ciphertext = encrypt_aes_cbc(message_to_encrypt_padded, ORACLE_KEY, ORACLE_IV)
        messages_encrypted.append(ciphertext)

    return messages_encrypted

def cbc_padding_oracle(ciphertext):
    plaintext_padded = decrypt_aes_cbc(ciphertext, ORACLE_KEY, ORACLE_IV)
    return valid_pkcs7_padding(plaintext_padded)
    
def attack_byte(previous_block, attacked_block, so_far_bytes):
    # indices start backwards
    byte_ix = len(so_far_bytes) + 1
    assert byte_ix >= 1 and byte_ix <= 16

    possible_guesses = []
    for guess in range(256):
        block_ending = [guess] + so_far_bytes
        block_flip = [0] * (BLOCK_SIZE - len(block_ending)) + block_ending
        block_padding_flip = [0] * (BLOCK_SIZE - byte_ix) + [byte_ix] * byte_ix

        block_flip_delta = xor(block_flip, block_padding_flip)
        crafted_previous_block = xor(previous_block, block_flip_delta)

        to_check = crafted_previous_block + attacked_block
        valid_padding = cbc_padding_oracle(to_check)
        if valid_padding:
            possible_guesses.append(guess)

    return possible_guesses


def attack_block(message, block_ix):
    # message is a list of blocks
    assert len(message[block_ix]) == BLOCK_SIZE, "this block has a weird size"
    
    # corner case, attacking first block, previous_block is IV
    if block_ix == 0:
        previous_block = ORACLE_IV
    else:
        previous_block = message[block_ix - 1]

    attacked_block = message[block_ix]

    possible_paths = [[]]
    for byte_ix in range(BLOCK_SIZE):
        new_paths = []
        for so_far_bytes in possible_paths:
            guesses = attack_byte(previous_block, attacked_block, so_far_bytes)

            for g in guesses:
                new_paths.append([g] + so_far_bytes)

        possible_paths = new_paths

    possible_plaintext_blocks = [bytearray(i) for i in possible_paths]
    assert len(possible_plaintext_blocks) == 1

    return possible_plaintext_blocks[0]

def attack_message(message):
    blocks = chunks_of_bytearray(message, BLOCK_SIZE)

    plaintext = []
    for ix, _ in enumerate(blocks):
        plaintext_block = attack_block(blocks, ix)
        plaintext.extend(plaintext_block)

    return unpad_pkcs7(bytearray(plaintext))

def main():
    messages_encrypted = cbc_encryption_oracle()

    for mes_enc in messages_encrypted:
        plaintext = attack_message(mes_enc)
        print(plaintext)

    print("challenge 3.17 completed.")

if __name__ == '__main__':
    main()