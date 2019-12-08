import sys
sys.path.insert(0, '../set_1_basics')
from utils import string_to_bytearray


def pkcs7_pad(bt, new_length):
    if len(bt) > new_length:
        raise Exception("already too big to pad")

    pad = new_length - len(bt)

    bytearray_copy = bytearray(bt)
    bytearray_copy.extend([pad] * pad)
    assert len(bytearray_copy) == new_length

    return bytearray_copy

def pad_to_modulo(bt, m):
    r = len(bt) % m
    return pkcs7_pad(bt, len(bt) + m - r)

def pad_to_mod_16(bt):
    return pad_to_modulo(bt, 16)

def valid_pkcs7_padding(bt):
    last_byte = bt[-1]

    if last_byte == 0:
        return False

    if last_byte > 16:
        return False

    pad = bt[len(bt)-last_byte:]
    for p in pad:
        if p != last_byte:
            return False

    return True

def unpad_pkcs7(bt):
    if valid_pkcs7_padding(bt):
        return bt[:len(bt) - int(bt[-1])]
    else:
        raise ValueError("padding is not valid")

def main():
    block = string_to_bytearray("YELLOW SUBMARINE")
    expected_pad_20 = string_to_bytearray("YELLOW SUBMARINE\x04\x04\x04\x04")

    padded = pkcs7_pad(block, 20)
    if padded == expected_pad_20:
        print("challenge 2.9 completed.")
    else:
        print("challenge 2.9 failed.")

if __name__ == '__main__':
    main()