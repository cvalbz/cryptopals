import sys
sys.path.insert(0, '../set_1_basics')
from utils import crypto_random_bytes, base64_to_bytearray, string_to_bytearray
from aes_ecb_mode import encrypt_aes_128_ecb, decrypt_aes_128_ecb
from pkcs7_padding import pad_to_mod_16, unpad_pkcs7
from ecb_cbc_detection_oracle import detection_oracle

oracle_key = crypto_random_bytes(16)
target_email = "fooXX@bar.com"

def parse_url_params(url_string):
    kv_pairs = url_string.split("&")
    return dict([kv.split("=") for kv in kv_pairs])

assert parse_url_params("foo=bar&baz=qux&zap=zazzle") == {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}

def profile_for(email):
    email = email.replace("&", "")
    email = email.replace("=", "")
    return f"email={email}&uid=10&role=user"

def encrypt_profile_for(email):
    profile = string_to_bytearray(profile_for(email))
    to_encrypt = pad_to_mod_16(profile)
    return encrypt_aes_128_ecb(to_encrypt, oracle_key)

def decrypt_encoded_profile(encoded_profile):
    plaintext = decrypt_aes_128_ecb(encoded_profile, oracle_key)
    profile = unpad_pkcs7(plaintext)
    return parse_url_params(profile.decode())

def main():
    encrypted_target_profile = encrypt_profile_for(target_email)
    # last block encrypted is "user" + "\x0c" * 12

    encrypted_crafted_profile = encrypt_profile_for( (16-len("email="))*"A" + "admin" + "\x0b"*11 )
    # second block encrypted is "admin" + "\x0b" * 11

    admin_profile = encrypted_target_profile
    admin_profile[len(admin_profile)-16:] = encrypted_crafted_profile[16:32]

    if decrypt_encoded_profile(admin_profile)['role'] == 'admin':
        print("challenge 2.13 completed.")
    else:
        print("challenge 2.13 failed.")

if __name__ == '__main__':
    main()