import convert_hex_to_base64 as ch1
import fixed_xor as ch2
import single_byte_xor_cipher as ch3
import detect_single_character_xor as ch4
import repeating_key_xor as ch5
import break_repeating_key_xor as ch6
import aes_ecb_mode as ch7
import detect_aes_in_ecb_mode as ch8

def main():
    ch1.main()
    ch2.main()
    ch3.main()
    ch4.main()
    ch5.main()
    ch6.main()
    ch7.main()
    ch8.main()

if __name__ == '__main__':
    main()