from utils import string_to_bytearray, xor, bytearray_to_hex_string

text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
message = string_to_bytearray(text)
key_string = "ICE"
key = string_to_bytearray(key_string)
expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

def encrypt_repeating_key(m, k):
    key_multiplier = len(m) // len(k)
    key_candidate = k * key_multiplier
    key_candidate += k[:len(m)-len(key_candidate)]

    xored = xor(m, key_candidate)
    return xored

def main():
    xored = encrypt_repeating_key(message, key)
    if bytearray_to_hex_string(xored) == expected:
        print("challenge 1.5 completed.")
    else:
        print("challenge 1.5 failed.")

if __name__ == '__main__':
    main()