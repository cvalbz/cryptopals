from utils import hex_string_to_bytearray, xor
from utils import alpha_and_printable_heuristic
from single_byte_xor_cipher import xor_cipher, brute_force_xor
from operator import itemgetter

def brute_force_messages(messages, heuristic_func):
    for message in messages:
        yield from brute_force_xor(message, heuristic_func)    

def detect_xor_cipher(messages, heuristic_func):
    candidates = brute_force_messages(messages, heuristic_func)
    return max(candidates, key=itemgetter(0))
    
def main():
    with open("4.txt", 'r') as f: lines = f.readlines()
    hex_lines = [l.replace("\n", "") for l in lines]
    ciphertexts = [hex_string_to_bytearray(i) for i in hex_lines]

    score, message, key = detect_xor_cipher(ciphertexts, alpha_and_printable_heuristic)
    print("challenge 1.4 message: %s" % message)

if __name__ == '__main__':
    main()