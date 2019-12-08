import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
import hashlib
import hmac as hmac_library
from utils import hex_string_to_bytearray as hs2b

class Server:
    def __init__(self):
        self.N = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
        self.g = 2
        self.k = 3
        self.I = 'valentinbuza@cryptopals.com'
        self.P = 'secure_password'

        self.salt = random_integer(0, 2**32)
        s = str(self.salt) + self.P
        xH = hashlib.sha256(s.encode('ascii')).hexdigest()
        x = int(xH, 16)
        self.v = pow(self.g, x, self.N)

    def send_salt_pub_key(self):
        self.b = random_integer(0, self.N - 1)
        self.B = (self.k * self.v + pow(self.g, self.b, self.N)) % self.N

        return (self.salt, self.B)

    def generate_K(self, email, A):
        s = str(A) + str(self.B)
        self.uH = hashlib.sha256(s.encode('ascii')).hexdigest()
        self.u = int(self.uH, 16)

        S = pow((A * pow(self.v, self.u, self.N)), self.b, self.N)
        self.K = hs2b(hashlib.sha256(str(S).encode('ascii')).hexdigest())

    def verify_mac(self, mac_received):
        mac = hmac_library.new(self.K, str(self.salt).encode('ascii'), hashlib.sha256).hexdigest()
        return hmac_library.compare_digest(mac, mac_received)

class Client:
    def __init__(self):
        self.N = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
        self.g = 2
        self.k = 3
        self.I = 'valentinbuza@cryptopals.com'
        self.P = 'secure_password'

    def send_email_pub_key(self):
        self.a = random_integer(0, self.N - 1)
        self.A = pow(self.g, self.a, self.N)

        return (self.I, self.A)

    def generate_K(self, salt, B):
        self.salt = salt
        s_ab = str(self.A) + str(B)
        self.uH = hashlib.sha256(s_ab.encode('ascii')).hexdigest()
        self.u = int(self.uH, 16)

        s_sp = str(salt) + self.P
        xH = hashlib.sha256(s_sp.encode('ascii')).hexdigest()
        x = int(xH, 16)

        S = pow((B - self.k * pow(self.g, x, self.N)), (self.a + self.u * x), self.N)
        self.K = hs2b(hashlib.sha256(str(S).encode('ascii')).hexdigest())

    def send_mac(self):
        mac = hmac_library.new(self.K, str(self.salt).encode('ascii'), hashlib.sha256).hexdigest()
        return mac

def main():
    client = Client()
    server = Server()

    email, client_pub_key = client.send_email_pub_key()
    salt, server_pub_key = server.send_salt_pub_key()

    client.generate_K(salt, server_pub_key)
    server.generate_K(email, client_pub_key)

    mac = client.send_mac()
    ok = server.verify_mac(mac)

    if ok:
        print("challenge 5.36 completed.")
    else:
        print("challenge 5.36 failed.")

if __name__ == "__main__":
    main()