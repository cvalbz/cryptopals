from utils import hex_string_to_bytearray, xor
from utils import alpha_and_printable_heuristic
from operator import itemgetter

ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def xor_cipher(message, byte_key):
    key = [byte_key] * len(message)
    xored = xor(message, key)
    return xored

def brute_force_xor(message, heuristic_func):
    for byte_candidate in range(0, 256):
        message_candidate = xor_cipher(message, byte_candidate)
        score = heuristic_func(message_candidate)
        yield score, message_candidate, byte_candidate

def break_xor_cipher(message, heuristic_func):
    candidates = brute_force_xor(message, heuristic_func)
    return max(candidates, key=itemgetter(0))

def main():
    bt_ciphertext = hex_string_to_bytearray(ciphertext)
    score, message, key = break_xor_cipher(bt_ciphertext, alpha_and_printable_heuristic)
    print("challenge 1.3 message: %s" % message)

if __name__ == '__main__':
    main()