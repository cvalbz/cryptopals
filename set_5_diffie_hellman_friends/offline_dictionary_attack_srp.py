import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
import hashlib
import hmac as hmac_library
from secure_remote_password import Server, Client
from utils import hex_string_to_bytearray as hs2b

class ServerU(Server):
    def __init__(self):
        super().__init__()
        self.P = 'antoinette' # password from dictionary

    def send_salt_pub_key(self):
        self.b = random_integer(0, self.N - 1)
        self.B = pow(self.g, self.b, self.N)
        self.u = random_integer(1, 2**128-1)

        return (self.salt, self.B, self.u)

class ClientU(Client):
    def __init__(self):
        super().__init__()
        self.P = 'antoinette' # password from dictionary

    def generate_K(self, salt, B, u):
        self.salt = salt
        self.u = u

        s_sp = str(salt) + self.P
        xH = hashlib.sha256(s_sp.encode('ascii')).hexdigest()
        x = int(xH, 16)

        S = pow(B, self.a + self.u * x, self.N)
        self.K = hs2b(hashlib.sha256(str(S).encode('ascii')).hexdigest())

class Adversary:
    def __init__(self, salt, server_pub_key, u):
        self.N = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
        self.g = 2

        self.salt = salt
        self.server_pub_key = server_pub_key
        self.u = u

    def mitm_pose_as_server(self):
        self.mitm_salt = random_integer(0, 2**32)

        self.mitm_b = random_integer(0, self.N - 1)
        self.mitm_server_pub_key = pow(self.g, self.mitm_b, self.N)
        self.mitm_u = random_integer(1, 2**128-1)

        return (self.mitm_salt, self.mitm_server_pub_key, self.mitm_u)

    def offline_dictionary_attack(self, controlled_mac, A):
        with open('/usr/share/dict/words', 'r') as f:
            w_lines = f.readlines()
        words = [w.strip().lower() for w in w_lines]

        for word in words:
            s_sp = str(self.mitm_salt) + word
            xH = hashlib.sha256(s_sp.encode('ascii')).hexdigest()
            x = int(xH, 16)
            self.v = pow(self.g, x, self.N)
            S = pow((A * pow(self.v, self.mitm_u, self.N)), self.mitm_b, self.N)
            self.K = hs2b(hashlib.sha256(str(S).encode('ascii')).hexdigest())

            mac = hmac_library.new(self.K, str(self.mitm_salt).encode('ascii'), hashlib.sha256).hexdigest()
            if mac == controlled_mac:
                print(f'found password: {word}')
                return word

        raise('offline dictionary attack failed')

def main():
    client = ClientU()
    server = ServerU()

    email, client_pub_key = client.send_email_pub_key()
    salt, server_pub_key, u = server.send_salt_pub_key()

    adversary = Adversary(salt, server_pub_key, u)
    mitm_salt, mitm_server_pub_key, mitm_u = adversary.mitm_pose_as_server()

    client.generate_K(mitm_salt, mitm_server_pub_key, mitm_u)
    server.generate_K(email, client_pub_key)

    controlled_mac = client.send_mac()
    ok = server.verify_mac(controlled_mac)

    password = adversary.offline_dictionary_attack(controlled_mac, client_pub_key)

    if password == 'antoinette':
        print("challenge 5.38 completed.")
    else:
        print("challenge 5.38 failed.")

if __name__ == "__main__":
    main()