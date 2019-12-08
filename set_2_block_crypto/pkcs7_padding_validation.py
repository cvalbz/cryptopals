import sys
sys.path.insert(0, '../set_1_basics')
from utils import string_to_bytearray
from pkcs7_padding import valid_pkcs7_padding, unpad_pkcs7

def main():
    s1 = string_to_bytearray("ICE ICE BABY\x04\x04\x04\x04")
    s2 = string_to_bytearray("ICE ICE BABY\x05\x05\x05\x05")
    s3 = string_to_bytearray("ICE ICE BABY\x01\x02\x03\x04")

    assert valid_pkcs7_padding(s1) == True
    assert valid_pkcs7_padding(s2) == False
    assert valid_pkcs7_padding(s3) == False

    unpad_pkcs7(s1)

    try:
        unpad_pkcs7(s2)
        raise Exception("challenge 2.15 failed.")
    except ValueError as e:
        pass

    try:
        unpad_pkcs7(s3)
        raise Exception("challenge 2.15 failed.")
    except ValueError as e:
        pass

    print("challenge 2.15 completed.")

if __name__ == '__main__':
    main()