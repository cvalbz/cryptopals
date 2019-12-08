from utils import hex_string_to_bytearray, xor, bytearray_to_hex_string

hex_a = "1c0111001f010100061a024b53535009181c"
hex_b = "686974207468652062756c6c277320657965"
hex_expected = "746865206b696420646f6e277420706c6179"

def main():
    bt_a = hex_string_to_bytearray(hex_a)
    bt_b = hex_string_to_bytearray(hex_b)
    bt_expected = xor(bt_a, bt_b)
    bt_expected_hex = bytearray_to_hex_string(bt_expected)

    if bt_expected_hex == hex_expected:
        print("challenge 1.2 completed.")
    else:
        print("challenge 1.2 failed.")

if __name__ == '__main__':
    main()