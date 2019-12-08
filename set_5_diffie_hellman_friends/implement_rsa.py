import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
from Crypto.PublicKey import RSA as LibraryRSA
import codecs

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def rsa_string_to_integer(s):
    hs = '0x' + codecs.encode(bytes(s, 'ascii'), 'hex').decode()
    return int(hs, 16)

def rsa_integer_to_string(i):
    s = hex(i)[2:]
    if len(s) % 2 == 1:
        s = '0' + s

    return codecs.decode(s, 'hex').decode()

class RSA:
    def __init__(self, n_length, e=3):
        self.n_length = n_length
        self.e = e

    def generate_keys(self):
        RSAkey = LibraryRSA.generate(self.n_length, e=self.e)

        self.p = getattr(RSAkey.key, 'p')
        self.q = getattr(RSAkey.key, 'q')
        self.N = self.p * self.q

        self.et = (self.p - 1) * (self.q - 1)

        self.d = modinv(self.e, self.et)
        assert self.d is not None, 'modinv failed'

        self.public_key = (self.N, self.e)
        self.private_key = (self.N, self.d)

    def encrypt(self, plaintext, encode=True):
        if encode:
            to_encrypt = rsa_string_to_integer(plaintext) # convert string to integer
        else:
            to_encrypt = plaintext # assume 'plaintext' is an integer

        return pow(to_encrypt, self.e, self.N)

    def decrypt(self, ciphertext, encode=True):
        decrypted = pow(ciphertext, self.d, self.N)

        if encode:
            message = rsa_integer_to_string(decrypted) # convert integer to string
        else:
            message = decrypted # assume 'message' is an integer

        return message

def main():
    rsa = RSA(2048)
    rsa.generate_keys()

    message = "SATOSHI NAKAMOTO"
    c = rsa.encrypt(message)
    m = rsa.decrypt(c)

    if m == message:
        print("challenge 5.39 completed.")
    else:
        print("challenge 5.39 failed.")

if __name__ == "__main__":
    main()