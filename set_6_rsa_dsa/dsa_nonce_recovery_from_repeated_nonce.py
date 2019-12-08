import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from utils import random_integer
from implement_rsa import modinv
import hashlib
from dsa_recovery_from_nonce import DSA, recover_secret_key, P, Q, G
import itertools

def read_data():
    lines = open('44.txt', 'r').readlines()
    lines = [i.replace('\n', '') for i in lines]

    signatures = [lines[i*4:(i+1)*4] for i in range(len(lines)/4)]
    return [parse_signature(i) for i in signatures]

def parse_signature(sig):
    return dict([parse_line(i) for i in sig])

def parse_line(line):
    if line.startswith('r: '):
        return ('r', int(line[3:]))
    if line.startswith('s: '):
        return ('s', int(line[3:]))
    if line.startswith('m: '):
        return ('m', line[3:])
    if line.startswith('msg: '):
        return ('msg', line[5:])

def recover_secret_key_repeated_nonce(signatures):
    y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
            "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
            "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
            "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
            "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
            "2971c3de5084cce04a2e147821", 16)

    pairs = itertools.product(signatures, signatures)
    for a, b in pairs:
        if a['msg'] == b['msg']:
            continue

        h1 = int(a['m'], 16)
        h2 = int(b['m'], 16)

        s1 = a['s']
        s2 = b['s']

        try:
            k_candidate = (((h1-h2)%Q) * modinv((s1-s2)%Q, Q)) % Q
        except:
            pass

        secret_key = recover_secret_key(k_candidate, (a['r'], a['s']), a['msg'])
        if pow(G, secret_key, P) == y:
            return secret_key

    return None

def main():
    signatures = read_data()

    secret_key = recover_secret_key_repeated_nonce(signatures)
    fingerprint = hashlib.sha1(hex(secret_key)[2:-1]).hexdigest()

    if fingerprint == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52':
        print("challenge 5.44 completed.")
    else:
        print("challenge 5.44 failed.")

if __name__ == "__main__":
    main()