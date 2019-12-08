from utils import hex_string_to_bytearray, bytearray_to_base64

hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

def main():
    bt = hex_string_to_bytearray(hex_string)
    b64 = bytearray_to_base64(bt)
    if b64 == expected:
        print("challenge 1.1 completed.")
    else:
        print("challenge 1.1 failed.")

if __name__ == '__main__':
    main()