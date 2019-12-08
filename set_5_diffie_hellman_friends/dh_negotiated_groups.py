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
    'p, g',
    'ACK',
    'A',
    'B',
    'A->B message',
    'B->A message'
]

def do_nothing(message_type, message):
    return message

ADVERSARY_STATE = {}
def active_adversary_g_1(message_type, message):
    if message_type == 'p, g':
        p, g = message

        ADVERSARY_STATE['p'] = p
        ADVERSARY_STATE['g'] = g

        return (p, 1)
    elif message_type == 'ACK':
        return message
    elif message_type == 'A':
        return message
    elif message_type == 'B':
        return message
    elif message_type == 'A->B message':
        return message
    elif message_type == 'B->A message':
        return message

ADVERSARY_STATE_2 = {}
def active_adversary_g_p(message_type, message):
    if message_type == 'p, g':
        p, g = message

        ADVERSARY_STATE_2['p'] = p
        ADVERSARY_STATE_2['g'] = g

        return (p, p)
    elif message_type == 'ACK':
        return message
    elif message_type == 'A':
        return message
    elif message_type == 'B':
        return message
    elif message_type == 'A->B message':
        return message
    elif message_type == 'B->A message':
        return message

ADVERSARY_STATE_3 = {}
def active_adversary_g_p_minus_1(message_type, message):
    if message_type == 'p, g':
        p, g = message

        ADVERSARY_STATE_3['p'] = p
        ADVERSARY_STATE_3['g'] = g

        return (p, p-1)
    elif message_type == 'ACK':
        return message
    elif message_type == 'A':
        return message
    elif message_type == 'B':
        return message
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
    message_type = 'p, g'
    message = (alice.p, alice.g)
    for_bob = send_A_to_B(alice, bob, message_type, message, do_nothing)

    bob.p = for_bob[0]
    bob.g = for_bob[1]
    bob.generate_keys()

    # 2nd message
    message_type = 'ACK'
    message = 'ACK'
    _ = send_B_to_A(alice, bob, message_type, message, do_nothing)
    print("Bob params: p = %s, g = %s" % (bob.p, bob.g))

    # 3rd message
    message_type = 'A'
    message = alice.public_key
    for_bob = send_A_to_B(alice, bob, message_type, message, do_nothing)
    bob.compute_shared_secret(for_bob)

    # 4th message
    message_type = 'B'
    message = bob.public_key
    for_alice = send_A_to_B(alice, bob, message_type, message, do_nothing)
    alice.compute_shared_secret(for_alice)

    # 5th message
    message_type = 'A->B message'
    message = alice.send_encrypted_message(s2b('YELLOW SUBMARINE'))
    for_bob = send_A_to_B(alice, bob, message_type, message, do_nothing)
    print(bob.receive_encrypted_message(for_bob[0], for_bob[1]))

    # 6th message
    message_type = 'B->A message'
    message = bob.send_encrypted_message(s2b('SATOSHI NAKAMOTO'))
    for_alice = send_A_to_B(alice, bob, message_type, message, do_nothing)
    print(alice.receive_encrypted_message(for_alice[0], for_alice[1]))

def mitm_attack_1():
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
    message_type = 'p, g'
    message = (alice.p, alice.g)
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_1)

    bob.p = for_bob[0]
    bob.g = for_bob[1]
    bob.generate_keys()

    # 2nd mesage
    message_type = 'ACK'
    message = 'ACK'
    _ = send_B_to_A(alice, bob, message_type, message, active_adversary_g_1)
    print("Bob params: p = %s, g = %s" % (bob.p, bob.g))

    # 3rd message
    message_type = 'A'
    message = alice.public_key
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_1)
    bob.compute_shared_secret(for_bob)
    print('Bob shared secret: %s' % bob.shared_secret)

    # 4th message
    message_type = 'B'
    message = bob.public_key
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary_g_1)
    alice.compute_shared_secret(for_alice)
    print('Alice shared secret: %s' % alice.shared_secret)

    # 5th message
    message_type = 'A->B message'
    message = alice.send_encrypted_message(s2b('YELLOW SUBMARINE'))
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_1)
    print(f'\nReceived by Bob: {bob.receive_encrypted_message(for_bob[0], for_bob[1])}')

    key = hex_string_to_bytearray(sha1(s2b('1')))[:16]
    decrypted = decrypt_aes_cbc(for_bob[0], key, for_bob[1])
    print(f'Decrypted by Mallory: {decrypted}')
    win_condition = decrypted == b'YELLOW SUBMARINE'

    # 6th message
    message_type = 'B->A message'
    message = bob.send_encrypted_message(s2b('SATOSHI NAKAMOTO'))
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary_g_1)
    print(f'\nReceived by Alice: {alice.receive_encrypted_message(for_alice[0], for_alice[1])}')

    return win_condition

def mitm_attack_2():
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
    message_type = 'p, g'
    message = (alice.p, alice.g)
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p)

    bob.p = for_bob[0]
    bob.g = for_bob[1]
    bob.generate_keys()

    # 2nd mesage
    message_type = 'ACK'
    message = 'ACK'
    _ = send_B_to_A(alice, bob, message_type, message, active_adversary_g_p)
    print(f"Bob params: p = {bob.p}, g = {bob.g}")

    # 3rd message
    message_type = 'A'
    message = alice.public_key
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p)
    bob.compute_shared_secret(for_bob)
    print(f'Bob shared secret: {bob.shared_secret}')

    # 4th message
    message_type = 'B'
    message = bob.public_key
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p)
    alice.compute_shared_secret(for_alice)
    print(f'Alice shared secret: {alice.shared_secret}')

    # 5th message
    message_type = 'A->B message'
    message = alice.send_encrypted_message(s2b('YELLOW SUBMARINE'))
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p)
    print(f'\nReceived by Bob: {bob.receive_encrypted_message(for_bob[0], for_bob[1])}')

    key = hex_string_to_bytearray(sha1(s2b('0')))[:16]
    decrypted = decrypt_aes_cbc(for_bob[0], key, for_bob[1])
    print(f'Decrypted by Mallory: {decrypted}')
    win_condition = decrypted == b'YELLOW SUBMARINE'

    # 6th message
    message_type = 'B->A message'
    message = bob.send_encrypted_message(s2b('SATOSHI NAKAMOTO'))
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p)
    print(f'\nReceived by Alice: {alice.receive_encrypted_message(for_alice[0], for_alice[1])}')

    return win_condition

def mitm_attack_3():
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
    message_type = 'p, g'
    message = (alice.p, alice.g)
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p_minus_1)

    bob.p = for_bob[0]
    bob.g = for_bob[1]
    bob.generate_keys()

    # 2nd mesage
    message_type = 'ACK'
    message = 'ACK'
    _ = send_B_to_A(alice, bob, message_type, message, active_adversary_g_p_minus_1)
    print(f"Bob params: p = {bob.p}, g = {bob.g}")

    # 3rd message
    message_type = 'A'
    message = alice.public_key
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p_minus_1)
    bob.compute_shared_secret(for_bob)
    print(f'Bob shared secret: {bob.shared_secret}')

    # 4th message
    message_type = 'B'
    message = bob.public_key
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p_minus_1)
    alice.compute_shared_secret(for_alice)
    print(f'Alice shared secret: {alice.shared_secret}')

    # 5th message
    message_type = 'A->B message'
    message = alice.send_encrypted_message(s2b('YELLOW SUBMARINE'))
    for_bob = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p_minus_1)
    print(f'\nReceived by Bob: {bob.receive_encrypted_message(for_bob[0], for_bob[1])}')

    key = key = hex_string_to_bytearray(sha1(s2b('1')))[:16]
    decrypted = decrypt_aes_cbc(for_bob[0], key, for_bob[1])
    print(f'Decrypted by Mallory: {decrypted}')
    win_condition_1 = decrypted == b'YELLOW SUBMARINE'

    key = hex_string_to_bytearray(sha1(s2b(str(ADVERSARY_STATE_3['p']-1))))[:16]
    decrypted = decrypt_aes_cbc(for_bob[0], key, for_bob[1])
    print(f'Decrypted by Mallory: {decrypted}')
    win_condition_2 = decrypted == b'YELLOW SUBMARINE'

    # 6th message
    message_type = 'B->A message'
    message = bob.send_encrypted_message(s2b('SATOSHI NAKAMOTO'))
    for_alice = send_A_to_B(alice, bob, message_type, message, active_adversary_g_p_minus_1)
    print(f'\nReceived by Alice: {alice.receive_encrypted_message(for_alice[0], for_alice[1])}')

    return win_condition_1 or win_condition_2

def main():
    honest_interaction()
    print('#'*50 + '    MITM attack with g = 1    ' + '#'*50)
    attack_1 = mitm_attack_1()
    print('#'*50 + '    MITM attack with g = p    ' + '#'*50)
    attack_2 = mitm_attack_2()
    print('#'*50 + '    MITM attack with g = p-1    ' + '#'*50)
    attack_3 = mitm_attack_3()

    if attack_1 and attack_2 and attack_3:
        print("challenge 5.35 completed.")
    else:
        print("challenge 5.35 failed.")

if __name__ == "__main__":
    main()