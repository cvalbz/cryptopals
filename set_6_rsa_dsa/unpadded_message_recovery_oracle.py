import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from utils import random_integer
from implement_rsa import RSA, modinv, rsa_string_to_integer, rsa_integer_to_string

ORACLE_KEY = RSA(2048, e=3)
ORACLE_KEY.generate_keys()

ORACLE_HISTORY = [] # prevent submission of the same ciphertext twice

def unpadded_message_oracle(ciphertext):
    if ciphertext in ORACLE_HISTORY:
        raise Exception('i have already seen this ciphertext')

    message = ORACLE_KEY.decrypt(ciphertext)
    ORACLE_HISTORY.append(ciphertext)

    return message

def exploit_oracle(ciphertext):
    n = ORACLE_KEY.N
    e = ORACLE_KEY.e

    s = random_integer(2, n-1)
    crafted_c = (pow(s, e, n) * ciphertext) % n

    crafted_p = unpadded_message_oracle(crafted_c)
    crafted_p = rsa_string_to_integer(crafted_p)

    plaintext = (crafted_p * modinv(s, n)) % n

    return rsa_integer_to_string(plaintext)

def main():
    message = 'SATOSHI NAKAMOTO'
    ciphertext = ORACLE_KEY.encrypt(message)

    oracle_message = unpadded_message_oracle(ciphertext)
    assert oracle_message == message

    adversary_message = exploit_oracle(ciphertext)

    if adversary_message == message:
        print("challenge 5.41 completed.")
    else:
        print("challenge 5.41 failed.")

if __name__ == "__main__":
    main()