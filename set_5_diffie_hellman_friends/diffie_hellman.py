import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
sys.path.insert(0, '../set_4_stream_crypto_randomness')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray, string_to_bytearray, hex_string_to_bytearray
from aes_cbc_mode import decrypt_aes_cbc, encrypt_aes_cbc
from sha1_keyed_mac import sha1
from hashed_mac import hmac

def modexp(a, x, p):
    return pow(a,x,p)

class HonestCryptographer:
    def __init__(self, p, g, q = None):
        self.p = p
        self.g = g
        self.q = q

    def generate_keys(self, subgroup=False):
        if not subgroup:
            self.secret_key = random_integer(0, self.p - 1)
            self.public_key = modexp(self.g, self.secret_key, self.p)
        else:
            self.secret_key = random_integer(0, self.q)
            self.public_key = modexp(self.g, self.secret_key, self.p)

    def compute_shared_secret(self, other_party_pub_key):
        self.shared_secret = modexp(other_party_pub_key, self.secret_key, self.p)

    def hkdf(self):
        ss = string_to_bytearray(str(self.shared_secret))
        return hex_string_to_bytearray(sha1(ss))[:16]

    def send_encrypted_message(self, message):
        key = self.hkdf()
        iv = crypto_random_bytes(16)

        ciphertext = encrypt_aes_cbc(message, key, iv)
        return ciphertext, iv

    def receive_encrypted_message(self, ciphertext, iv):
        key = self.hkdf()
        return decrypt_aes_cbc(ciphertext, key, iv)

    def send_mac(self, message):
        key = self.hkdf()
        return hmac(key, message)

    def receive_mac(self, message, mac):
        key = self.hkdf()
        tag = hmac(key, message)
        return tag == mac # unsafe

def main():
    p =     int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
                "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
                "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
                "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
                "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
                "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
                "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
                "fffffffffffff", 16)
    g = 2

    alice = HonestCryptographer(p, g)
    bob   = HonestCryptographer(p, g)

    alice.generate_keys()
    bob.generate_keys()

    alice.compute_shared_secret(bob.public_key)
    bob.compute_shared_secret(alice.public_key)

    if alice.shared_secret == bob.shared_secret:
        print("challenge 5.33 completed.")
    else:
        print("challenge 5.33 failed.")

if __name__ == "__main__":
   main()