import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
sys.path.insert(0, '../set_4_stream_crypto_randomness')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
from diffie_hellman import HonestCryptographer
from aes_cbc_mode import decrypt_aes_cbc, encrypt_aes_cbc
from sha1_keyed_mac import sha1
from utils import string_to_bytearray as s2b
from utils import hex_string_to_bytearray

MESSAGE_TYPES = [
    'p, g, A',
    'B',
    'A->B message',
    'B->A message'
]

def do_nothing(message_type, message):
    return message

ADVERSARY_STATE = {}
def active_adversary(message_type, message):
    if message_type == 'p, g, A':
        p, g, A = message

        ADVERSARY_STATE['p'] = p
        ADVERSARY_STATE['g'] = g

        return (p, g, p)
    elif message_type == 'B':
        B = message
        return ADVERSARY_STATE['p']
    elif message_type == 'A->B message':
        return message
    elif message_type == 'B->A message':
        return message


def send_A_to_B(alice, bob, message_type, message, mallory_function):
    modified_message = mallory_function(message_type, message)
    return modified_message

def send_B_to_A(alice, bob, message_type, message, mallory_function):
    modified_message = mallory_function(message_type, message)
    return modified_message

def honest_interaction():
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff", 16)
    g = 2


    # initial phase
    alice = HonestCryptographer(p, g)
    alice.generate_keys()
    bob = HonestCryptographer(1,1) # inactive party with dummy params

    # 1st message
    message_type = 'p, g, A'
    message = (alice.p, alice.g, alice.public_key)
    for_bob = send_A_to_B(alice, bob, message_type, message, do_nothing)

    bob.p = for_bob[0]
    bob.g = for_bob[1]
    bob.generate_keys()
    bob.compute_shared_secret(for_bob[2])

    # 2nd message
    message_type = 'B'
    message = bob.public_key
    for_alice = send_A_to_B(alice, bob, message_type, message, do_nothing)
    alice.compute_shared_secret(for_alice)

    # 3rd message
    message_type = 'A->B message'
    message = alice.send_encrypted_message(s2b('YELLOW SUBMARINE'))
    for_bob = send_A_to_B(alice, bob, message_type, message, do_nothing)
    print(bob.receive_encrypted_message(for_bob[0], for_bob[1]))

    # 4th message
    message_type = 'B->A message'
    message = bob.send_encrypted_message(s2b('SATOSHI NAKAMOTO'))
    for_alice = send_A_to_B(alice, bob, message_type, message, do_nothing)
    print(alice.receive_encrypted_message(for_alice[0], for_alice[1]))

def mitm_attack():
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff", 16)
    g = 2


    # initial phase
    alice = HonestCryptographer(p, g)
    alice.generate_keys()
    bob = HonestCryptographer(1,1) # inactive party with dummy params

    # 1st message
    message_type = 'p, g, A'
    message = (alice.p, alice.g, alice.public_key)
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary)

    bob.p = for_bob[0]
    bob.g = for_bob[1]
    bob.generate_keys()
    bob.compute_shared_secret(for_bob[2])
    print(f'Bob shared secret: {bob.shared_secret}')

    # 2nd message
    message_type = 'B'
    message = bob.public_key
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary)
    alice.compute_shared_secret(for_alice)
    print(f'Alice shared secret: {alice.shared_secret}')

    # 3rd message
    message_type = 'A->B message'
    message = alice.send_encrypted_message(s2b('YELLOW SUBMARINE'))
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary)
    print(f'\nReceived by Bob: {bob.receive_encrypted_message(for_bob[0], for_bob[1])}')

    key = hex_string_to_bytearray(sha1(s2b('0')))[:16]
    print(f'Decrypted by Mallory: {decrypt_aes_cbc(for_bob[0], key, for_bob[1])}')

    # 4th message
    message_type = 'B->A message'
    message = bob.send_encrypted_message(s2b('SATOSHI NAKAMOTO'))
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary)
    print(f'\nReceived by Alice: {alice.receive_encrypted_message(for_alice[0], for_alice[1])}')

    key = hex_string_to_bytearray(sha1(s2b('0')))[:16]
    decrypted = decrypt_aes_cbc(for_alice[0], key, for_alice[1])
    print(f'Decrypted by Mallory: {decrypted}\n')

    if decrypted == b"SATOSHI NAKAMOTO":
        print("challenge 5.34 completed.")
    else:
        print("challenge 5.34 failed.")

def main():
    honest_interaction()
    print('#'*50)
    mitm_attack()

if __name__ == "__main__":
    main()