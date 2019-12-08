import sys
sys.setrecursionlimit(1500)
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from utils import random_integer
from implement_rsa import RSA, modinv, rsa_string_to_integer, rsa_integer_to_string
import hashlib
import re
import sympy

# 15-byte ASN.1 value for SHA1 (from rfc 3447)
ASN1_SHA1 = '3021300906052b0e03021a05000414'

class RSA_Signature_PKCS_1_5:
    def __init__(self, s, e=3):
        self.key = RSA(s, e=e)
        self.key.generate_keys()

        self.key_length_bytes = s / 8

    def sign(self, message):
        h = hashlib.sha1(message).hexdigest()
        to_sign = '0001' + 'ff' * (self.key_length_bytes - 38) + '00' + ASN1_SHA1 + h
        to_sign_integer = rsa_string_to_integer(to_sign.decode('hex'))

        signature = self.key.decrypt(to_sign_integer, encode=False)
        return signature

    def insecure_verify(self, signature, message):
        m = self.key.encrypt(signature, encode=False)
        m = rsa_integer_to_string(m).encode('hex')
        m = '00'*(self.key_length_bytes-len(m)/2) + m

        h = hashlib.sha1(message).hexdigest()
        regex = '0001(ff)*00' + ASN1_SHA1 + h
        if re.search(regex, m) is not None:
            return True
        else:
            return False

def forge_signature(message):
    h = hashlib.sha1(message).hexdigest()
    to_forge = '0001ff00' + ASN1_SHA1 + h + '00'*(128-39)
    to_forge = rsa_string_to_integer(to_forge.decode('hex'))

    f = sympy.integer_nthroot(to_forge, 3)[0] + 1
    return f


def main():
    signer = RSA_Signature_PKCS_1_5(1024, e=3)
    message = 'SATOSHI NAKAMOTO'

    signature = signer.sign(message)
    verify = signer.insecure_verify(signature, message)
    assert verify is True

    f = forge_signature('hi mom')
    forged_verify = signer.insecure_verify(f, 'hi mom')

    if forged_verify:
        print("challenge 5.42 completed.")
    else:
        print("challenge 5.42 failed.")

if __name__ == "__main__":
    main()