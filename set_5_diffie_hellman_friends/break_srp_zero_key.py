import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
import hashlib
import hmac as hmac_library
from secure_remote_password import Server, Client
from utils import hex_string_to_bytearray as hs2b

class ClientWithZeroKey(Client):
    def __init__(self):
        super().__init__()
        self.P = None # bypass authentication without password

    def send_email_pub_key(self):
        return (self.I, 0)

    def generate_K(self, salt, B):
        self.salt = salt

        S = 0
        self.K = hs2b(hashlib.sha256(str(S).encode('ascii')).hexdigest())

class ClientWith_N_Key(ClientWithZeroKey):
    def send_email_pub_key(self):
        m = random_integer(0, 10)
        return (self.I, self.N * m)

def main():
    ######## auth with zero key ########
    client = ClientWithZeroKey()
    server = Server()

    email, client_pub_key = client.send_email_pub_key()
    salt, server_pub_key = server.send_salt_pub_key()

    client.generate_K(salt, server_pub_key)
    server.generate_K(email, client_pub_key)

    mac = client.send_mac()
    ok = server.verify_mac(mac)
    if ok:
        print("authenticated successfully with a zero key")
        ex1 = True
    else:
        print("authentication with a zero key failed")
        ex1 = False

    ######## auth with multiple of N ########
    client = ClientWith_N_Key()
    server = Server()

    email, client_pub_key = client.send_email_pub_key()
    salt, server_pub_key = server.send_salt_pub_key()

    client.generate_K(salt, server_pub_key)
    server.generate_K(email, client_pub_key)

    mac = client.send_mac()
    ok = server.verify_mac(mac)
    if ok:
        print("authenticated successfully with multiple of N")
        ex2 = True
    else:
        print("authentication with multiple of N failed")
        ex2 = False

    if ex1 and ex2:
        print("challenge 5.37 completed.")
    else:
        print("challenge 5.37 failed.")

if __name__ == "__main__":
    main()