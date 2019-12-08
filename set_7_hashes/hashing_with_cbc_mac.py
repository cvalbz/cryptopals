import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
from cbc_mac_message_forgery import cbc_mac_sign, cbc_mac_verify, SHARED_KEY
from utils import crypto_random_bytes, xor
import itertools

def cbc_mac_hash_function(message):
    return cbc_mac_sign(message, SHARED_KEY)

def test_function():
    tag = cbc_mac_hash_function("alert('MZA who was that?');\n\x04\x04\x04\x04")
    assert str(tag).encode('hex') == '296b8d7cb78a243dda4d0a61d33bbdd1'

def forge_hash():
    known_message  = "alert('MZA who was that?');\n\x04\x04\x04\x04"

    #for printable_chars in itertools.product(range(32, 127), repeat=7):
    if True:
        #free_bytes = "".join([chr(i) for i in printable_chars])
        free_bytes = "/  $8]t"
        chosen_message = "alert('Ayo, the Wu is back!'); /" + free_bytes + "\x09" * 9

        prefix_hash = cbc_mac_hash_function(chosen_message)
        crafted = chosen_message + xor(bytearray(known_message[:16]), prefix_hash) + known_message[16:]

        scrambled = crafted[48:64]
        if all([(i>=32 and i <= 127) for i in scrambled]):
            return crafted


def main():
    test_function()

    collision = forge_hash()
    print "collision is: %s" % collision

    if str(cbc_mac_hash_function(collision)).encode('hex') == '296b8d7cb78a243dda4d0a61d33bbdd1':
        print("challenge 7.50 completed.")
    else:
        print("challenge 7.50 failed.")

if __name__ == '__main__':
    main()